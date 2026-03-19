import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { MessageSquare, Send, Loader2, ChevronDown, ChevronRight, Bot, User, Wrench, ArrowLeft } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { cn, formatDate } from "@/lib/utils";
import type { Mission, Conversation, Message } from "@/types";
import { useState, useEffect, useRef } from "react";

interface ToolCallData {
  name?: string;
  arguments?: string;
  status?: string;
  output?: string;
}

export default function Conversations() {
  const { id: missionId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [selectedConvId, setSelectedConvId] = useState<string | null>(null);
  const [inputText, setInputText] = useState("");
  const [isSending, setIsSending] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const { data: mission } = useQuery({
    queryKey: ["mission", missionId],
    queryFn: () => api.get<Mission>(`/missions/${missionId}`),
    enabled: !!missionId,
  });

  const { data: convData, isLoading: convsLoading } = useQuery({
    queryKey: ["conversations", missionId],
    queryFn: () => api.get<{ conversations: Conversation[] }>(`/missions/${missionId}/conversations`),
    enabled: !!missionId,
    refetchInterval: 10000,
  });

  const conversations = convData?.conversations ?? [];

  // Auto-select first conversation
  useEffect(() => {
    if (!selectedConvId && conversations.length > 0) {
      setSelectedConvId(conversations[0].id);
    }
  }, [conversations, selectedConvId]);

  const { data: msgData, isLoading: msgsLoading } = useQuery({
    queryKey: ["messages", selectedConvId],
    queryFn: () => api.get<{ messages: Message[] }>(`/conversations/${selectedConvId}/messages`),
    enabled: !!selectedConvId,
    refetchInterval: 3000,
  });

  const messages = msgData?.messages ?? [];

  // Auto-scroll on new messages
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  const sendMutation = useMutation({
    mutationFn: (content: string) =>
      api.post<Message>(`/conversations/${selectedConvId}/messages`, { role: "user", content }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", selectedConvId] });
      setInputText("");
      setIsSending(false);
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to send message");
      setIsSending(false);
    },
  });

  const handleSend = () => {
    const text = inputText.trim();
    if (!text || !selectedConvId || isSending) return;
    setIsSending(true);
    sendMutation.mutate(text);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="flex h-[calc(100vh-5rem)] flex-col">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] pb-4 mb-4">
        <button
          onClick={() => navigate(`/missions/${missionId}`)}
          className="rounded-lg p-1.5 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] hover:text-[var(--color-foreground)]"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <div>
          <h1 className="text-2xl font-bold">Mission Chat</h1>
          <p className="text-sm text-[var(--color-muted-foreground)]">
            {mission?.name ?? "Loading..."}
          </p>
        </div>
      </div>

      <div className="flex flex-1 gap-4 overflow-hidden">
        {/* Left sidebar: conversation list */}
        <div className="w-72 shrink-0 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] flex flex-col overflow-hidden">
          <div className="border-b border-[var(--color-border)] px-4 py-3">
            <h2 className="text-sm font-semibold">Conversations</h2>
          </div>
          <div className="flex-1 overflow-y-auto">
            {convsLoading ? (
              <div className="flex items-center justify-center p-8">
                <Loader2 className="h-5 w-5 animate-spin text-[var(--color-muted-foreground)]" />
              </div>
            ) : conversations.length > 0 ? (
              <div className="divide-y divide-[var(--color-border)]">
                {conversations.map((conv) => (
                  <button
                    key={conv.id}
                    onClick={() => setSelectedConvId(conv.id)}
                    className={cn(
                      "w-full px-4 py-3 text-left transition-colors hover:bg-[var(--color-accent)]",
                      selectedConvId === conv.id && "bg-[var(--color-primary)]/10"
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <MessageSquare className="h-4 w-4 shrink-0 text-[var(--color-muted-foreground)]" />
                      <span className="truncate text-sm font-medium">
                        {conv.title || `Conversation ${conv.id.slice(0, 8)}`}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center gap-2 text-xs text-[var(--color-muted-foreground)]">
                      {conv.agent_type && (
                        <span className="rounded bg-[var(--color-primary)]/10 px-1.5 py-0.5 text-[var(--color-primary)]">
                          {conv.agent_type}
                        </span>
                      )}
                      {conv.status && (
                        <span className="capitalize">{conv.status}</span>
                      )}
                      <span>{formatDate(conv.created_at)}</span>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center text-sm text-[var(--color-muted-foreground)]">
                <MessageSquare className="mx-auto h-8 w-8 opacity-30" />
                <p className="mt-2">No conversations yet</p>
              </div>
            )}
          </div>
        </div>

        {/* Right panel: chat */}
        <div className="flex flex-1 flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] overflow-hidden">
          {selectedConvId ? (
            <>
              {/* Messages */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {msgsLoading ? (
                  <div className="flex items-center justify-center h-full">
                    <Loader2 className="h-6 w-6 animate-spin text-[var(--color-muted-foreground)]" />
                  </div>
                ) : messages.length > 0 ? (
                  <>
                    {messages.map((msg) => (
                      <ChatMessage key={msg.id} message={msg} />
                    ))}
                    {isSending && (
                      <div className="flex items-start gap-3">
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--color-primary)]/10">
                          <Bot className="h-4 w-4 text-[var(--color-primary)]" />
                        </div>
                        <div className="rounded-lg bg-[var(--color-muted)]/30 px-4 py-3">
                          <div className="flex items-center gap-2 text-sm text-[var(--color-muted-foreground)]">
                            <Loader2 className="h-4 w-4 animate-spin" />
                            Thinking...
                          </div>
                        </div>
                      </div>
                    )}
                    <div ref={messagesEndRef} />
                  </>
                ) : (
                  <div className="flex h-full items-center justify-center">
                    <div className="text-center">
                      <MessageSquare className="mx-auto h-12 w-12 opacity-20 text-[var(--color-muted-foreground)]" />
                      <p className="mt-3 text-sm text-[var(--color-muted-foreground)]">
                        No messages yet. Start the conversation.
                      </p>
                    </div>
                  </div>
                )}
              </div>

              {/* Input area */}
              <div className="border-t border-[var(--color-border)] p-4">
                <div className="flex gap-3">
                  <textarea
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Send a message..."
                    rows={1}
                    className="flex-1 resize-none rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-2.5 text-sm placeholder:text-[var(--color-muted-foreground)] focus:border-[var(--color-primary)] focus:outline-none"
                  />
                  <button
                    onClick={handleSend}
                    disabled={!inputText.trim() || isSending}
                    className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-4 py-2.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50"
                  >
                    {isSending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Send className="h-4 w-4" />
                    )}
                    Send
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="flex h-full items-center justify-center">
              <div className="text-center">
                <MessageSquare className="mx-auto h-16 w-16 opacity-20 text-[var(--color-muted-foreground)]" />
                <p className="mt-4 text-[var(--color-muted-foreground)]">
                  Select a conversation to view messages
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ChatMessage({ message }: { message: Message }) {
  const isUser = message.role === "user";
  const isTool = message.role === "tool";
  const [toolExpanded, setToolExpanded] = useState(false);

  // Parse tool_calls if present
  let toolCalls: ToolCallData[] = [];
  if (message.tool_calls) {
    try {
      toolCalls = Array.isArray(message.tool_calls)
        ? message.tool_calls
        : typeof message.tool_calls === "string"
          ? JSON.parse(message.tool_calls)
          : [message.tool_calls];
    } catch {
      // ignore parse errors
    }
  }

  if (isTool) {
    return (
      <div className="mx-8">
        <button
          onClick={() => setToolExpanded(!toolExpanded)}
          className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-muted)]/20 px-3 py-2 text-xs text-[var(--color-muted-foreground)] hover:bg-[var(--color-muted)]/40 transition-colors w-full text-left"
        >
          <Wrench className="h-3.5 w-3.5 shrink-0" />
          <span className="font-medium">Tool Result</span>
          {message.tool_call_id && (
            <span className="font-mono text-[var(--color-primary)]">{message.tool_call_id.slice(0, 12)}</span>
          )}
          {toolExpanded ? <ChevronDown className="h-3.5 w-3.5 ml-auto" /> : <ChevronRight className="h-3.5 w-3.5 ml-auto" />}
        </button>
        {toolExpanded && message.content && (
          <pre className="mt-1 max-h-48 overflow-auto rounded-lg border border-[var(--color-border)] bg-[#0D0D12] p-3 text-xs font-mono text-zinc-300">
            {message.content}
          </pre>
        )}
      </div>
    );
  }

  return (
    <div className={cn("flex items-start gap-3", isUser && "flex-row-reverse")}>
      {/* Avatar */}
      <div
        className={cn(
          "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg",
          isUser ? "bg-cyan-500/10" : "bg-[var(--color-primary)]/10"
        )}
      >
        {isUser ? (
          <User className="h-4 w-4 text-cyan-400" />
        ) : (
          <Bot className="h-4 w-4 text-[var(--color-primary)]" />
        )}
      </div>

      {/* Message bubble */}
      <div
        className={cn(
          "max-w-[75%] rounded-lg px-4 py-3",
          isUser
            ? "bg-cyan-500/15 text-[var(--color-foreground)]"
            : "bg-[var(--color-muted)]/30 text-[var(--color-foreground)]"
        )}
      >
        {message.content && (
          <div className="text-sm leading-relaxed whitespace-pre-wrap">
            {message.content}
          </div>
        )}

        {/* Tool calls within assistant messages */}
        {toolCalls.length > 0 && (
          <div className="mt-3 space-y-2">
            {toolCalls.map((tc, idx) => (
              <ToolCallBadge key={idx} toolCall={tc} />
            ))}
          </div>
        )}

        {/* Metadata */}
        <div
          className={cn(
            "mt-2 flex items-center gap-2 text-xs text-[var(--color-muted-foreground)]",
            isUser && "justify-end"
          )}
        >
          {message.model && <span>{message.model}</span>}
          {message.provider && <span className="capitalize">{message.provider}</span>}
          <span>{formatDate(message.created_at)}</span>
        </div>
      </div>
    </div>
  );
}

function ToolCallBadge({ toolCall }: { toolCall: ToolCallData }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)]/50">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-2 px-3 py-2 text-xs text-left hover:bg-[var(--color-muted)]/20 transition-colors"
      >
        <Wrench className="h-3.5 w-3.5 shrink-0 text-blue-400" />
        <span className="font-medium text-blue-400">{toolCall.name || "Tool Call"}</span>
        {toolCall.status && (
          <span
            className={cn(
              "rounded-full px-1.5 py-0.5 text-xs font-semibold",
              toolCall.status === "success"
                ? "bg-emerald-500/15 text-emerald-400"
                : toolCall.status === "error"
                  ? "bg-[#FF3366]/15 text-[#FF3366]"
                  : "bg-zinc-500/15 text-zinc-400"
            )}
          >
            {toolCall.status}
          </span>
        )}
        {expanded ? <ChevronDown className="h-3 w-3 ml-auto" /> : <ChevronRight className="h-3 w-3 ml-auto" />}
      </button>
      {expanded && (
        <div className="border-t border-[var(--color-border)] p-3 space-y-2">
          {toolCall.arguments && (
            <div>
              <p className="text-xs font-semibold text-[var(--color-muted-foreground)] mb-1">Arguments</p>
              <pre className="rounded-lg bg-[#0D0D12] p-2 text-xs font-mono text-zinc-300 overflow-auto max-h-32">
                {typeof toolCall.arguments === "string"
                  ? toolCall.arguments
                  : JSON.stringify(toolCall.arguments, null, 2)}
              </pre>
            </div>
          )}
          {toolCall.output && (
            <div>
              <p className="text-xs font-semibold text-[var(--color-muted-foreground)] mb-1">Output</p>
              <pre className="rounded-lg bg-[#0D0D12] p-2 text-xs font-mono text-zinc-300 overflow-auto max-h-48">
                {toolCall.output}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
