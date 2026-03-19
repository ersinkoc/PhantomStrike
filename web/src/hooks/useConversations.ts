import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export interface Conversation {
  id: string;
  mission_id: string;
  title?: string;
  agent_type?: string;
  status: string;
  metadata?: any;
  created_at: string;
  updated_at: string;
}

export interface Message {
  id: string;
  conversation_id: string;
  role: "system" | "user" | "assistant" | "tool";
  content?: string;
  tool_calls?: any;
  tool_call_id?: string;
  tokens_used?: number;
  model?: string;
  provider?: string;
  created_at: string;
}

export interface SendMessageInput {
  content: string;
}

const CONV_KEY = "conversations";

export function useConversations(missionId: string) {
  return useQuery({
    queryKey: [CONV_KEY, missionId],
    queryFn: async () => {
      const data = await api.get<{ conversations: Conversation[] }>(`/missions/${missionId}/conversations`);
      return data;
    },
    enabled: !!missionId,
  });
}

export function useConversation(id: string) {
  return useQuery({
    queryKey: [CONV_KEY, "detail", id],
    queryFn: async () => {
      const data = await api.get<Conversation>(`/conversations/${id}`);
      return data;
    },
    enabled: !!id,
  });
}

export function useMessages(conversationId: string, limit = 50, offset = 0) {
  return useQuery({
    queryKey: [CONV_KEY, conversationId, "messages", limit, offset],
    queryFn: async () => {
      const data = await api.get<{ messages: Message[] }>(
        `/conversations/${conversationId}/messages?limit=${limit}&offset=${offset}`
      );
      return data;
    },
    enabled: !!conversationId,
  });
}

export function useSendMessage(conversationId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: SendMessageInput) => {
      const data = await api.post<Message>(`/conversations/${conversationId}/messages`, input);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: [CONV_KEY, conversationId, "messages"],
      });
    },
  });
}
