import { describe, it, expect, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactNode } from 'react';
import { useMissions, useMission } from './useMissions';

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
  },
}));

describe('useMissions', () => {
  it('fetches missions list', async () => {
    const { api } = await import('@/lib/api');
    (api.get as any).mockResolvedValue({
      missions: [
        { id: '1', name: 'Test Mission', status: 'running', progress: 50 },
      ],
      total: 1,
    });

    const { result } = renderHook(() => useMissions(), { wrapper: createWrapper() });

    await waitFor(() => {
      expect(result.current.data?.missions).toHaveLength(1);
    });

    expect(result.current.data?.missions[0].name).toBe('Test Mission');
  });

  it('fetches single mission', async () => {
    const { api } = await import('@/lib/api');
    (api.get as any).mockResolvedValue({
      id: '1',
      name: 'Single Mission',
      status: 'completed',
      progress: 100,
    });

    const { result } = renderHook(() => useMission('1'), { wrapper: createWrapper() });

    await waitFor(() => {
      expect(result.current.data?.name).toBe('Single Mission');
    });
  });
});
