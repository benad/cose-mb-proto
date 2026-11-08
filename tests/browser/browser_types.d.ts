// Deno's bundled Node stream declarations reference this newer Streams callback.
// It is present in Deno's native web library, but absent from TypeScript's DOM library.
interface TransformerCancelCallback {
  (reason: unknown): void | PromiseLike<void>;
}
