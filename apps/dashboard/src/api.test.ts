import { afterEach, describe, expect, it, vi } from "vitest";
import { scanDemo, scanSource, scanUrl } from "./api";

const sampleScan = {
  id: "scan-1",
  target_type: "source",
  target: "/workspace/app",
  status: "completed",
  started_at: "2026-07-18T12:00:00Z",
  completed_at: "2026-07-18T12:00:01Z",
  duration_ms: 1000,
  summary: {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    confirmed: 0,
  },
  findings: [],
  limitations: [],
  metadata: {},
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("scan API client", () => {
  it("sends a source path as JSON", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(sampleScan), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(scanSource("/workspace/app")).resolves.toMatchObject({ id: "scan-1" });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/scans/source",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ path: "/workspace/app" }) }),
    );
  });

  it("sends a public URL to the URL endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ...sampleScan, target_type: "url" }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await scanUrl("https://example.com");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/scans/url",
      expect.objectContaining({ body: JSON.stringify({ url: "https://example.com" }) }),
    );
  });

  it("surfaces an API detail without leaking response markup", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "Private network targets are not allowed." }), {
          status: 422,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(scanDemo()).rejects.toThrow("Private network targets are not allowed.");
  });
});
