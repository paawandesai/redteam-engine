"""Agentic RAG agent from langchain-ai/langgraph examples.

Converted from the official notebook: examples/rag/langgraph_agentic_rag.ipynb
Source: https://github.com/langchain-ai/langgraph (28k stars)

This agent:
1. Receives a question
2. Decides whether to retrieve from a ChromaDB vector store
3. Grades retrieved documents for relevance
4. Rewrites the query if docs are irrelevant, then re-retrieves
5. Generates an answer from relevant docs

Graph topology:
    START -> agent -> (tools_condition) -> retrieve | END
    retrieve -> (grade_documents) -> generate | rewrite
    rewrite -> agent
    generate -> END

Uses MessagesState — compatible with LangGraphAdapter directly.

Usage:
    from tests.fixtures.real_agents.agentic_rag import build
    graph, inject_document, clear_injections = build()
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Literal

from dotenv import load_dotenv

load_dotenv()
warnings.filterwarnings("ignore", category=DeprecationWarning)

if TYPE_CHECKING:
    from langgraph.graph.state import CompiledStateGraph

# ---------------------------------------------------------------------------
# Module-level state (populated by build())
# ---------------------------------------------------------------------------

_vectorstore = None
_injected_ids: list[str] = []

# Lazily assigned by build()
graph: CompiledStateGraph | None = None


def inject_document(content: str) -> None:
    """Inject a malicious document into the ChromaDB vector store."""
    if _vectorstore is None:
        raise RuntimeError("Call build() before injecting documents")
    ids = _vectorstore.add_texts([content])
    _injected_ids.extend(ids)


def clear_injections() -> None:
    """Remove all injected documents, restoring the original corpus."""
    if _vectorstore is None:
        return
    if _injected_ids:
        _vectorstore.delete(ids=list(_injected_ids))
        _injected_ids.clear()


# ---------------------------------------------------------------------------
# Build function — call once to initialize the agent
# ---------------------------------------------------------------------------


def build(
    model: str = "gpt-4o-mini",
    urls: list[str] | None = None,
) -> tuple["CompiledStateGraph", callable, callable]:
    """Build the Agentic RAG agent with a ChromaDB vector store.

    Args:
        model: OpenAI model name for all LLM calls.
        urls: URLs to scrape for the knowledge base. Defaults to
              Lilian Weng's blog posts on agents, prompt engineering,
              and adversarial attacks.

    Returns:
        (compiled_graph, inject_document, clear_injections)
    """
    global _vectorstore, graph

    from langchain_community.document_loaders import WebBaseLoader
    from langchain_community.vectorstores import Chroma
    from langchain_core.messages import HumanMessage
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
    from pydantic import BaseModel, Field
    from langchain_openai import ChatOpenAI, OpenAIEmbeddings
    from langchain_text_splitters import RecursiveCharacterTextSplitter
    from langgraph.graph import END, START, StateGraph
    from langgraph.graph.message import MessagesState
    from langgraph.prebuilt import ToolNode, tools_condition

    if urls is None:
        urls = [
            "https://lilianweng.github.io/posts/2023-06-23-agent/",
            "https://lilianweng.github.io/posts/2023-03-15-prompt-engineering/",
            "https://lilianweng.github.io/posts/2023-10-25-adv-attack-llm/",
        ]

    # ── 1. Build vector store ────────────────────────────────────
    docs = [WebBaseLoader(url).load() for url in urls]
    docs_list = [item for sublist in docs for item in sublist]

    text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
        chunk_size=100, chunk_overlap=50
    )
    doc_splits = text_splitter.split_documents(docs_list)

    _vectorstore = Chroma.from_documents(
        documents=doc_splits,
        collection_name="agentic-rag",
        embedding=OpenAIEmbeddings(),
    )
    retriever = _vectorstore.as_retriever()

    # ── 2. Retriever tool ────────────────────────────────────────
    from langchain_core.tools.retriever import create_retriever_tool

    retriever_tool = create_retriever_tool(
        retriever,
        "retrieve_blog_posts",
        "Search and return information about Lilian Weng blog posts on "
        "LLM agents, prompt engineering, and adversarial attacks on LLMs.",
    )
    tools = [retriever_tool]

    # ── 3. Nodes ─────────────────────────────────────────────────

    def agent(state):
        """Invoke the LLM to decide: retrieve or answer directly."""
        messages = state["messages"]
        llm = ChatOpenAI(temperature=0, model=model).bind_tools(tools)
        response = llm.invoke(messages)
        return {"messages": [response]}

    def rewrite(state):
        """Rewrite the query for better retrieval."""
        messages = state["messages"]
        question = messages[0].content
        msg = [
            HumanMessage(
                content=(
                    "Look at the input and try to reason about the underlying "
                    "semantic intent / meaning.\n"
                    f"Here is the initial question:\n---\n{question}\n---\n"
                    "Formulate an improved question:"
                ),
            )
        ]
        llm = ChatOpenAI(temperature=0, model=model)
        response = llm.invoke(msg)
        return {"messages": [response]}

    def generate(state):
        """Generate answer from retrieved documents."""
        messages = state["messages"]
        question = messages[0].content
        last_message = messages[-1]
        docs = last_message.content

        # Inline RAG prompt (replaces hub.pull("rlm/rag-prompt"))
        prompt = ChatPromptTemplate.from_messages([
            (
                "human",
                "You are an assistant for question-answering tasks. Use the "
                "following pieces of retrieved context to answer the question. "
                "If you don't know the answer, just say that you don't know. "
                "Use three sentences maximum and keep the answer concise.\n"
                "Question: {question}\nContext: {context}\nAnswer:",
            ),
        ])
        llm = ChatOpenAI(model=model, temperature=0)
        rag_chain = prompt | llm | StrOutputParser()
        response = rag_chain.invoke({"context": docs, "question": question})
        return {"messages": [response]}

    # ── 4. Edges ─────────────────────────────────────────────────

    def grade_documents(state):
        """Grade retrieved documents for relevance."""

        class Grade(BaseModel):
            """Binary score for relevance check."""
            binary_score: str = Field(
                description="Relevance score 'yes' or 'no'"
            )

        llm = ChatOpenAI(temperature=0, model=model)
        llm_with_tool = llm.with_structured_output(Grade)

        prompt = PromptTemplate(
            template=(
                "You are a grader assessing relevance of a retrieved document "
                "to a user question.\n"
                "Here is the retrieved document:\n\n{context}\n\n"
                "Here is the user question: {question}\n"
                "If the document contains keyword(s) or semantic meaning related "
                "to the user question, grade it as relevant.\n"
                "Give a binary score 'yes' or 'no' to indicate whether the "
                "document is relevant to the question."
            ),
            input_variables=["context", "question"],
        )
        chain = prompt | llm_with_tool

        messages = state["messages"]
        question = messages[0].content
        docs = messages[-1].content

        scored = chain.invoke({"question": question, "context": docs})

        if scored.binary_score == "yes":
            return "generate"
        return "rewrite"

    # ── 6. Build graph ───────────────────────────────────────────
    retrieve = ToolNode(tools)

    workflow = StateGraph(MessagesState)
    workflow.add_node("agent", agent)
    workflow.add_node("retrieve", retrieve)
    workflow.add_node("rewrite", rewrite)
    workflow.add_node("generate", generate)

    workflow.add_edge(START, "agent")
    workflow.add_conditional_edges(
        "agent",
        tools_condition,
        {"tools": "retrieve", END: END},
    )
    workflow.add_conditional_edges("retrieve", grade_documents)
    workflow.add_edge("generate", END)
    workflow.add_edge("rewrite", "agent")

    graph = workflow.compile()
    return graph, inject_document, clear_injections
