import Editor, {
  DiffEditor,
  loader,
  type BeforeMount,
  type DiffOnMount,
  type OnMount,
} from "@monaco-editor/react";
import * as monaco from "monaco-editor/esm/vs/editor/editor.api";
import EditorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";
import { useEffect, useState } from "react";

import { Icon } from "./Icon";

const workerScope = self as typeof self & {
  MonacoEnvironment?: {
    getWorker: () => Worker;
  };
};

workerScope.MonacoEnvironment = {
  getWorker: () => new EditorWorker(),
};

loader.config({ monaco });

let configured = false;

const configureMonaco: BeforeMount = (instance) => {
  if (configured) {
    return;
  }

  configured = true;

  if (!instance.languages.getLanguages().some((language) => language.id === "lua")) {
    instance.languages.register({ id: "lua", extensions: [".lua", ".luau"] });
  }

  instance.languages.setLanguageConfiguration("lua", {
    comments: {
      lineComment: "--",
      blockComment: ["--[[", "]]"],
    },
    brackets: [
      ["{", "}"],
      ["[", "]"],
      ["(", ")"],
    ],
    autoClosingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"', notIn: ["string"] },
      { open: "'", close: "'", notIn: ["string", "comment"] },
    ],
    surroundingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"' },
      { open: "'", close: "'" },
    ],
  });

  instance.languages.setMonarchTokensProvider("lua", {
    defaultToken: "",
    tokenPostfix: ".lua",
    keywords: [
      "and",
      "break",
      "continue",
      "do",
      "else",
      "elseif",
      "end",
      "export",
      "false",
      "for",
      "function",
      "if",
      "in",
      "local",
      "nil",
      "not",
      "or",
      "repeat",
      "return",
      "then",
      "true",
      "type",
      "typeof",
      "until",
      "while",
    ],
    builtins: [
      "assert",
      "error",
      "getmetatable",
      "ipairs",
      "next",
      "pairs",
      "pcall",
      "print",
      "rawget",
      "rawset",
      "require",
      "select",
      "setmetatable",
      "string",
      "table",
      "task",
      "tonumber",
      "tostring",
      "type",
      "unpack",
      "xpcall",
    ],
    operators: [
      "+",
      "-",
      "*",
      "/",
      "%",
      "^",
      "#",
      "==",
      "~=",
      "<=",
      ">=",
      "<",
      ">",
      "=",
      ";",
      ":",
      ",",
      ".",
      "..",
      "...",
    ],
    symbols: /[=><!~?:&|+\-*/^%#.,;]+/,
    tokenizer: {
      root: [
        [/\s+/, "white"],
        [/--\[\[[\s\S]*?\]\]/, "comment"],
        [/--.*$/, "comment"],
        [/\[(=*)\[[\s\S]*?\]\1\]/, "string"],
        [/"([^"\\]|\\.)*"/, "string"],
        [/'([^'\\]|\\.)*'/, "string"],
        [/\b0[xX][0-9a-fA-F]+\b/, "number.hex"],
        [/\b0[bB][01]+\b/, "number.binary"],
        [/\b\d+(\.\d+)?([eE][+-]?\d+)?\b/, "number"],
        [
          /[a-zA-Z_][\w]*/,
          {
            cases: {
              "@keywords": "keyword",
              "@builtins": "type.identifier",
              "@default": "identifier",
            },
          },
        ],
        [/@symbols/, "delimiter"],
        [/[{}[\]()]/, "@brackets"],
      ],
    },
  });

  instance.editor.defineTheme("3ziz-dark", {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "comment", foreground: "7C8590", fontStyle: "italic" },
      { token: "keyword", foreground: "7FB3E0" },
      { token: "type.identifier", foreground: "6FC2B4" },
      { token: "identifier", foreground: "E6E8EA" },
      { token: "string", foreground: "9CC97E" },
      { token: "number", foreground: "D6A444" },
      { token: "number.hex", foreground: "D6A444" },
      { token: "number.binary", foreground: "D6A444" },
      { token: "delimiter", foreground: "8B929B" },
    ],
    colors: {
      "editor.background": "#16181B",
      "editor.foreground": "#E6E8EA",
      "editorLineNumber.foreground": "#6B7280",
      "editorLineNumber.activeForeground": "#A2A9B2",
      "editorCursor.foreground": "#5B9DD9",
      "editor.selectionBackground": "#5B9DD93A",
      "editor.inactiveSelectionBackground": "#5B9DD920",
      "editor.lineHighlightBackground": "#1C1F23",
      "editorIndentGuide.background1": "#272C33",
      "editorIndentGuide.activeBackground1": "#444C57",
      "editorWidget.background": "#1C1F23",
      "editorWidget.border": "#313740",
      "editorSuggestWidget.background": "#1C1F23",
      "editorGutter.background": "#16181B",
      "editorOverviewRuler.border": "#00000000",
      "scrollbarSlider.background": "#8B929B33",
      "scrollbarSlider.hoverBackground": "#8B929B55",
      "scrollbarSlider.activeBackground": "#8B929B77",
      "diffEditor.insertedTextBackground": "#5FBF8F26",
      "diffEditor.removedTextBackground": "#E0736E26",
      "diffEditor.insertedLineBackground": "#5FBF8F14",
      "diffEditor.removedLineBackground": "#E0736E14",
      "diffEditor.diagonalFill": "#22262B",
    },
  });
};

const commonOptions: monaco.editor.IStandaloneEditorConstructionOptions = {
  readOnly: true,
  domReadOnly: true,
  automaticLayout: true,
  scrollBeyondLastLine: false,
  smoothScrolling: true,
  wordWrap: "on",
  wrappingIndent: "same",
  fontFamily:
    '"Cascadia Code", "Cascadia Mono", "SFMono-Regular", Consolas, monospace',
  fontLigatures: true,
  fontSize: 13,
  lineHeight: 21,
  letterSpacing: 0.1,
  minimap: {
    enabled: true,
    scale: 1,
    showSlider: "mouseover",
  },
  padding: {
    top: 14,
    bottom: 18,
  },
  cursorBlinking: "solid",
  renderWhitespace: "selection",
  renderControlCharacters: true,
  stickyScroll: {
    enabled: true,
  },
  bracketPairColorization: {
    enabled: true,
  },
  guides: {
    bracketPairs: true,
    indentation: true,
  },
  overviewRulerBorder: false,
  hideCursorInOverviewRuler: true,
  contextmenu: true,
  folding: true,
  links: false,
  scrollbar: {
    verticalScrollbarSize: 11,
    horizontalScrollbarSize: 11,
    alwaysConsumeMouseWheel: false,
  },
};

function EditorLoading() {
  return (
    <div className="editor-loading" aria-label="Loading code viewer">
      <div className="editor-loading__gutter" />
      <div className="editor-loading__lines">
        <span />
        <span />
        <span />
        <span />
        <span />
      </div>
    </div>
  );
}

interface EmptyArtifactProps {
  title: string;
  detail: string;
}

export function EmptyArtifact({ title, detail }: EmptyArtifactProps) {
  return (
    <div className="artifact-empty">
      <span className="artifact-empty__icon">
        <Icon name="file" size={22} />
      </span>
      <div>
        <h3>{title}</h3>
        <p>{detail}</p>
      </div>
    </div>
  );
}

interface CodeSurfaceProps {
  value?: string | undefined;
  language?: string;
  ariaLabel: string;
  emptyTitle?: string;
  emptyDetail?: string;
  onMount?: OnMount | undefined;
}

export function CodeSurface({
  value,
  language = "lua",
  ariaLabel,
  emptyTitle = "Artifact unavailable",
  emptyDetail = "This analysis did not produce this artifact.",
  onMount,
}: CodeSurfaceProps) {
  if (!value) {
    return <EmptyArtifact title={emptyTitle} detail={emptyDetail} />;
  }

  return (
    <div className="code-surface">
      <Editor
        beforeMount={configureMonaco}
        {...(onMount ? { onMount } : {})}
        height="100%"
        language={language}
        loading={<EditorLoading />}
        options={{
          ...commonOptions,
          ariaLabel,
        }}
        theme="3ziz-dark"
        value={value}
      />
    </div>
  );
}

interface DiffSurfaceProps {
  original?: string | undefined;
  modified?: string | undefined;
  onMount?: DiffOnMount | undefined;
}

export function DiffSurface({
  original,
  modified,
  onMount,
}: DiffSurfaceProps) {
  const [sideBySide, setSideBySide] = useState(
    () => !window.matchMedia("(max-width: 1040px)").matches,
  );

  useEffect(() => {
    const media = window.matchMedia("(max-width: 1040px)");
    const update = () => setSideBySide(!media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  if (!original || !modified) {
    return (
      <EmptyArtifact
        title="Comparison unavailable"
        detail="Both original and readable source are required for a diff."
      />
    );
  }

  return (
    <div className="code-surface code-surface--diff">
      <DiffEditor
        beforeMount={configureMonaco}
        {...(onMount ? { onMount } : {})}
        height="100%"
        language="lua"
        loading={<EditorLoading />}
        modified={modified}
        options={{
          ...commonOptions,
          ariaLabel: "Original and readable source comparison",
          renderSideBySide: sideBySide,
          originalEditable: false,
          enableSplitViewResizing: true,
          renderOverviewRuler: false,
          diffWordWrap: "on",
          ignoreTrimWhitespace: false,
          minimap: { enabled: false },
        }}
        original={original}
        theme="3ziz-dark"
      />
    </div>
  );
}




