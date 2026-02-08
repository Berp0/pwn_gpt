from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .cli import analyze_path


def run_gui() -> None:
    root = tk.Tk()
    root.title("PWN Hacking Tool")
    root.geometry("640x480")

    path_var = tk.StringVar()
    output_var = tk.StringVar(value="text")

    def browse() -> None:
        filename = filedialog.askopenfilename(title="Select binary or archive")
        if filename:
            path_var.set(filename)

    def run_analysis() -> None:
        path = path_var.get().strip()
        if not path:
            messagebox.showwarning("Missing file", "Please select a binary or archive to analyze.")
            return
        try:
            report_text = analyze_path(path, output_var.get())
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Analysis failed", str(exc))
            return
        output.delete("1.0", tk.END)
        output.insert(tk.END, report_text)

    frame = ttk.Frame(root, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)

    top = ttk.Frame(frame)
    top.pack(fill=tk.X)

    ttk.Label(top, text="Binary/Archive:").pack(side=tk.LEFT)
    ttk.Entry(top, textvariable=path_var, width=50).pack(side=tk.LEFT, padx=5)
    ttk.Button(top, text="Browse", command=browse).pack(side=tk.LEFT)

    options = ttk.Frame(frame)
    options.pack(fill=tk.X, pady=8)
    ttk.Label(options, text="Output format:").pack(side=tk.LEFT)
    ttk.Combobox(options, textvariable=output_var, values=["text", "json", "markdown"], width=12).pack(
        side=tk.LEFT, padx=5
    )
    ttk.Button(options, text="Analyze", command=run_analysis).pack(side=tk.LEFT, padx=10)

    output = tk.Text(frame, wrap=tk.WORD)
    output.pack(fill=tk.BOTH, expand=True)

    root.mainloop()


if __name__ == "__main__":
    run_gui()
