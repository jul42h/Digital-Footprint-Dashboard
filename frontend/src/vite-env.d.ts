/// <reference types="vite/client" />

declare const __BUILD_STAMP__: string;

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
  readonly VITE_USE_API?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
