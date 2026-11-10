"""Project-owned disposable Tk window used for real screenshot evidence.

Prints one JSON line with its PID/geometry after the window is mapped, then
stays alive until stdin closes or it is terminated. It never captures anything
and displays only synthetic project text/graphics, never a real desktop.
"""

from __future__ import annotations

import json
import sys
import tkinter as tk


def main(argv: list[str]) -> int:
    text = "CTF-Solver synthetic window"
    width, height = 720, 420
    for index, value in enumerate(argv):
        if value == "--text" and index + 1 < len(argv):
            text = argv[index + 1]
        if value == "--size" and index + 1 < len(argv):
            try:
                w, h = argv[index + 1].lower().split("x")
                width, height = int(w), int(h)
            except ValueError:
                pass
    root = tk.Tk()
    root.title("CTF-Solver synthetic evidence window")
    root.geometry(f"{width}x{height}+80+80")
    canvas = tk.Canvas(root, width=width, height=height, bg="#f4f6f8", highlightthickness=0)
    canvas.pack(fill="both", expand=True)
    # A checkerboard guarantees non-blank pixel variance for honest capture checks.
    for y in range(0, height, 40):
        for x in range(0, width, 40):
            colour = "#dce6f2" if (x // 40 + y // 40) % 2 == 0 else "#c3d3e8"
            canvas.create_rectangle(x, y, x + 40, y + 40, fill=colour, outline="")
    canvas.create_text(
        width // 2,
        height // 2 - 20,
        text=text,
        font=("Consolas", 18, "bold"),
        fill="#102030",
        width=width - 80,
    )
    canvas.create_text(
        width // 2,
        height // 2 + 30,
        text="synthetic, project-owned window — no personal desktop content",
        font=("Consolas", 10),
        fill="#405060",
    )
    root.update_idletasks()
    root.update()
    info = {
        "event": "window_ready",
        "pid": root.winfo_id(),
        "process_pid": __import__("os").getpid(),
        "width": root.winfo_width(),
        "height": root.winfo_height(),
        "title": root.title(),
    }
    # The HWND belongs to the toplevel; the process is what PrintWindow needs.
    print(json.dumps(info), flush=True)
    try:
        root.mainloop()
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
