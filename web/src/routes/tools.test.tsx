import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Tools from '../routes/tools';

// Mock the API
vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    put: vi.fn(),
    post: vi.fn(),
  },
}));

const createTestQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

describe('Tools Page', () => {
  it('renders loading state', () => {
    const queryClient = createTestQueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <Tools />
      </QueryClientProvider>
    );

    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('renders tools grouped by category', async () => {
    const queryClient = createTestQueryClient();
    const { api } = await import('@/lib/api');

    (api.get as any).mockResolvedValue({
      tools: [
        { name: 'nmap', category: 'network/scanning', enabled: true, avg_exec_time: 30, success_rate: 95 },
        { name: 'nuclei', category: 'vuln/scanner', enabled: false, avg_exec_time: 120, success_rate: 90 },
      ],
    });

    render(
      <QueryClientProvider client={queryClient}>
        <Tools />
      </QueryClientProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('nmap')).toBeInTheDocument();
    });

    expect(screen.getByText('nuclei')).toBeInTheDocument();
    expect(screen.getByText(/network/)).toBeInTheDocument();
    expect(screen.getByText(/vuln/)).toBeInTheDocument();
  });
});
