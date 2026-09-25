import { analyzeFile } from "./analyze";

// Runs static analysis off the main thread so large files never freeze the UI.
self.onmessage = async (event: MessageEvent<{ id: number; file: File }>) => {
  const { id, file } = event.data;
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const report = await analyzeFile(bytes, file.name);
    self.postMessage({ id, ok: true, report });
  } catch (err) {
    self.postMessage({ id, ok: false, error: err instanceof Error ? err.message : String(err) });
  }
};
