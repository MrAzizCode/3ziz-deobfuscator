declare module "lzma-purejs" {
  interface InputStream {
    readByte(): number;
  }

  interface OutputStream {
    writeByte(value: number): void;
  }

  class Decoder {
    setDictionarySize(size: number): boolean;
    setLcLpPb(lc: number, lp: number, pb: number): boolean;
    code(input: InputStream, output: OutputStream, outputSize: number): boolean;
  }

  const api: {
    readonly LZMA: { readonly Decoder: typeof Decoder };
  };
  export default api;
}
