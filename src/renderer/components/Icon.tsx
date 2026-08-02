import type { SVGProps } from "react";

export type IconName =
  | "alert"
  | "arrow-right"
  | "cancel"
  | "check"
  | "chevron"
  | "code"
  | "compare"
  | "copy"
  | "download"
  | "file"
  | "folder"
  | "info"
  | "lock"
  | "refresh"
  | "report"
  | "search"
  | "shield"
  | "terminal"
  | "upload"
  | "validation"
  | "warning";

interface IconProps extends SVGProps<SVGSVGElement> {
  name: IconName;
  size?: number;
}

export function Icon({
  name,
  size = 18,
  className,
  ...props
}: IconProps) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
    className,
    ...props,
  };

  switch (name) {
    case "alert":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" />
          <path d="M12 7.6v5.3" />
          <path d="M12 16.5h.01" />
        </svg>
      );
    case "arrow-right":
      return (
        <svg {...common}>
          <path d="M5 12h14" />
          <path d="m14 7 5 5-5 5" />
        </svg>
      );
    case "cancel":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" />
          <path d="m9 9 6 6M15 9l-6 6" />
        </svg>
      );
    case "check":
      return (
        <svg {...common}>
          <path d="m5 12.5 4.1 4.1L19 6.8" />
        </svg>
      );
    case "chevron":
      return (
        <svg {...common}>
          <path d="m9 7 5 5-5 5" />
        </svg>
      );
    case "code":
      return (
        <svg {...common}>
          <path d="m8.5 7-5 5 5 5M15.5 7l5 5-5 5" />
          <path d="m13.5 4-3 16" />
        </svg>
      );
    case "compare":
      return (
        <svg {...common}>
          <path d="M8 5H4v14h4M16 5h4v14h-4" />
          <path d="M9 9h6M12 6l3 3-3 3" />
          <path d="M15 15H9M12 12l-3 3 3 3" />
        </svg>
      );
    case "copy":
      return (
        <svg {...common}>
          <rect x="8" y="8" width="11" height="11" rx="2" />
          <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
        </svg>
      );
    case "download":
      return (
        <svg {...common}>
          <path d="M12 3v12" />
          <path d="m7.5 10.5 4.5 4.5 4.5-4.5" />
          <path d="M5 20h14" />
        </svg>
      );
    case "file":
      return (
        <svg {...common}>
          <path d="M7 3h7l4 4v14H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" />
          <path d="M14 3v5h4M8.5 12h6M8.5 16h6" />
        </svg>
      );
    case "folder":
      return (
        <svg {...common}>
          <path d="M3.5 7.5h6l2-2h9v12.8a2.2 2.2 0 0 1-2.2 2.2H5.7a2.2 2.2 0 0 1-2.2-2.2Z" />
          <path d="M3.5 9h17" />
        </svg>
      );
    case "info":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" />
          <path d="M12 11v5M12 7.5h.01" />
        </svg>
      );
    case "lock":
      return (
        <svg {...common}>
          <rect x="5" y="10" width="14" height="10" rx="2" />
          <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2" />
        </svg>
      );
    case "refresh":
      return (
        <svg {...common}>
          <path d="M20 7v5h-5" />
          <path d="M18.2 16.2A8 8 0 1 1 20 12" />
        </svg>
      );
    case "report":
      return (
        <svg {...common}>
          <path d="M6 3h9l3 3v15H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" />
          <path d="M14 3v4h4M8 11h6M8 15h7M8 18h4" />
        </svg>
      );
    case "search":
      return (
        <svg {...common}>
          <circle cx="10.5" cy="10.5" r="6.5" />
          <path d="m15.5 15.5 4 4" />
        </svg>
      );
    case "shield":
      return (
        <svg {...common}>
          <path d="M12 3 5 6v5.3c0 4.5 2.7 7.5 7 9.7 4.3-2.2 7-5.2 7-9.7V6Z" />
          <path d="m8.7 12 2.1 2.1 4.6-4.7" />
        </svg>
      );
    case "terminal":
      return (
        <svg {...common}>
          <rect x="3" y="4" width="18" height="16" rx="2" />
          <path d="m7 9 3 3-3 3M12.5 15H17" />
        </svg>
      );
    case "upload":
      return (
        <svg {...common}>
          <path d="M12 16V4" />
          <path d="m7.5 8.5 4.5-4.5 4.5 4.5" />
          <path d="M5 20h14" />
        </svg>
      );
    case "validation":
      return (
        <svg {...common}>
          <path d="M9 3h6l1 2h3v16H5V5h3Z" />
          <path d="m8.5 13 2 2 5-5" />
        </svg>
      );
    case "warning":
      return (
        <svg {...common}>
          <path d="M12 3.5 21 20H3Z" />
          <path d="M12 9v4.5M12 17h.01" />
        </svg>
      );
  }
}
