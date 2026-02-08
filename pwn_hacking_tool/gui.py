from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .cli import OPTIONAL_TOOLS, REQUIRED_TOOLS, analyze_path


def run_gui() -> None:
    root = tk.Tk()
    root.title("PWN Hacking Tool")
    root.geometry("760x520")

    path_var = tk.StringVar()
    output_var = tk.StringVar(value="text")
    api_key_var = tk.StringVar()
    status_var = tk.StringVar(value="Ready.")

    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")

    def browse() -> None:
        filename = filedialog.askopenfilename(title="Select binary or archive")
        if filename:
            path_var.set(filename)
            status_var.set(f"Selected: {filename}")

    def run_analysis() -> None:
        path = path_var.get().strip()
        if not path:
            messagebox.showwarning("Missing file", "Please select a binary or archive to analyze.")
            return
        try:
            status_var.set("Analyzing...")
            root.update_idletasks()
            selected_tools = [
                tool for tool, var in tool_vars.items() if var.get()
            ]
            report_text = analyze_path(path, output_var.get(), selected_tools, api_key_var.get() or None)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Analysis failed", str(exc))
            status_var.set("Error during analysis.")
            return
        output.delete("1.0", tk.END)
        output.insert(tk.END, report_text)
        status_var.set("Analysis complete.")

    def copy_output() -> None:
        content = output.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("No output", "Nothing to copy yet.")
            return
        root.clipboard_clear()
        root.clipboard_append(content)
        status_var.set("Copied report to clipboard.")

    frame = ttk.Frame(root, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)

    top = ttk.Frame(frame)
    top.pack(fill=tk.X)

    ttk.Label(top, text="Binary/Archive:").pack(side=tk.LEFT)
    ttk.Entry(top, textvariable=path_var, width=60).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
    ttk.Button(top, text="Browse", command=browse).pack(side=tk.LEFT)

    options = ttk.Frame(frame)
    options.pack(fill=tk.X, pady=8)
    ttk.Label(options, text="Output format:").pack(side=tk.LEFT)
    ttk.Combobox(options, textvariable=output_var, values=["text", "json", "explain"], width=12).pack(
        side=tk.LEFT, padx=5
    )
    ttk.Button(options, text="Analyze", command=run_analysis).pack(side=tk.LEFT, padx=10)
    ttk.Button(options, text="Copy to clipboard", command=copy_output).pack(side=tk.LEFT)

    tool_frame = ttk.LabelFrame(frame, text="Tools")
    tool_frame.pack(fill=tk.X, pady=6)
    tool_vars: dict[str, tk.BooleanVar] = {}
    for tool in REQUIRED_TOOLS + OPTIONAL_TOOLS:
        var = tk.BooleanVar(value=True)
        tool_vars[tool] = var
        checkbox = ttk.Checkbutton(tool_frame, text=tool, variable=var)
        if tool in REQUIRED_TOOLS:
            checkbox.state(["disabled"])
        checkbox.pack(side=tk.LEFT, padx=4, pady=2)

    api_frame = ttk.Frame(frame)
    api_frame.pack(fill=tk.X, pady=4)
    ttk.Label(api_frame, text="API key (optional):").pack(side=tk.LEFT)
    ttk.Entry(api_frame, textvariable=api_key_var, width=40, show="*").pack(side=tk.LEFT, padx=5)

    output_frame = ttk.Frame(frame)
    output_frame.pack(fill=tk.BOTH, expand=True)
    output = tk.Text(output_frame, wrap=tk.WORD)
    scrollbar = ttk.Scrollbar(output_frame, command=output.yview)
    output.configure(yscrollcommand=scrollbar.set)
    output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    status = ttk.Label(frame, textvariable=status_var, anchor=tk.W)
    status.pack(fill=tk.X, pady=(6, 0))

    root.mainloop()


if __name__ == "__main__":
    run_gui()
