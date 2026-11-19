import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { AlertCircle, CheckCircle, Info, X } from "lucide-react";

type ToastItem = { id: number; type: "success" | "error" | "info"; message: string };

type ToastContextType = {
  toasts: ToastItem[];
  add: (type: ToastItem["type"], message: string) => void;
  remove: (id: number) => void;
};

const ToastContext = createContext<ToastContextType | null>(null);

const TONE: Record<ToastItem["type"], string> = {
  success: "border-emerald-500/60 bg-emerald-600/95",
  error: "border-red-500/60 bg-red-600/95",
  info: "border-sky-500/60 bg-sky-600/95",
};

const ICON: Record<ToastItem["type"], ReactNode> = {
  success: <CheckCircle className="h-5 w-5" />,
  error: <AlertCircle className="h-5 w-5" />,
  info: <Info className="h-5 w-5" />,
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const remove = useCallback((id: number) => {
    setToasts((current) => current.filter((item) => item.id !== id));
  }, []);

  const add = useCallback(
    (type: ToastItem["type"], message: string) => {
      const id = nextId.current++;
      setToasts((current) => [...current, { id, type, message }]);
      setTimeout(() => remove(id), 6000);
    },
    [remove],
  );

  return (
    <ToastContext.Provider value={{ toasts, add, remove }}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-[60] flex w-[min(92vw,380px)] flex-col gap-2">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto flex items-start gap-3 rounded-lg border px-4 py-3 text-sm text-white shadow-xl ${TONE[toast.type]}`}
            role="status"
          >
            <span className="mt-0.5 shrink-0">{ICON[toast.type]}</span>
            <span className="flex-1 break-words">{toast.message}</span>
            <button
              onClick={() => remove(toast.id)}
              className="shrink-0 rounded opacity-70 hover:opacity-100"
              aria-label="Dismiss notification"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider");
  return context;
}
