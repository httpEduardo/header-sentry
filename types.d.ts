declare module "fs" {
  const fs: {
    readFileSync(path: string, encoding: string): string;
  };
  export = fs;
}

declare const process: {
  argv: string[];
};
