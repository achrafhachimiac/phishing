// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import App from './App';

describe('App navigation', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    cleanup();
  });

  it('renders the THEPHISH tab and opens the dedicated workflow view', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({ authenticated: true }),
    } as Response);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /\[5\] thephish/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /\[5\] thephish/i }));

    expect(await screen.findByText(/thephish eml intake/i)).toBeInTheDocument();
  });
});