import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import pefile

def analyze_pe(file_path, output_text):
    try:
        pe = pefile.PE(file_path)
        output_text.delete(1.0, tk.END)  # Wyczyszczenie pola tekstowego
        output_text.insert(tk.END, f"=== Analiza pliku PE ===\n")
        output_text.insert(tk.END, f"Ścieżka pliku: {file_path}\n")
        output_text.insert(tk.END, f"Typ pliku: {'DLL' if pe.is_dll() else 'EXE'}\n")
        output_text.insert(tk.END, f"Liczba sekcji: {pe.FILE_HEADER.NumberOfSections}\n\n")

        output_text.insert(tk.END, "--- Sekcje ---\n")
        for section in pe.sections:
            output_text.insert(tk.END, f"  Nazwa: {section.Name.decode().strip()}\n")
            output_text.insert(tk.END, f"  Rozmiar: {section.Misc_VirtualSize}\n")
            output_text.insert(tk.END, f"  Adres: {hex(section.VirtualAddress)}\n\n")

        output_text.insert(tk.END, "--- Funkcje eksportowane ---\n")
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                output_text.insert(tk.END, f"  {export.name.decode()} (RVA: {hex(export.address)})\n")
        else:
            output_text.insert(tk.END, "  Brak funkcji eksportowanych.\n")

        output_text.insert(tk.END, "\n--- Funkcje importowane ---\n")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                output_text.insert(tk.END, f"Biblioteka: {entry.dll.decode()}\n")
                for imp in entry.imports:
                    output_text.insert(tk.END, f"  {imp.name.decode()} (RVA: {hex(imp.address)})\n")
        else:
            output_text.insert(tk.END, "  Brak funkcji importowanych.\n")
    except pefile.PEFormatError:
        messagebox.showerror("Błąd", "Niepoprawny plik PE lub format niezgodny.")
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się przeprowadzić analizy: {e}")

def load_file(output_text):
    file_path = filedialog.askopenfilename(
        title="Wybierz plik PE",
        filetypes=[("Pliki PE", "*.exe;*.dll"), ("Wszystkie pliki", "*.*")]
    )
    if file_path:
        analyze_pe(file_path, output_text)

# Creating App
def create_app():
    root = tk.Tk()
    root.title("Analiza plików PE")
    root.geometry("700x500")


    header = tk.Label(root, text="Analizator plików PE", font=("Arial", 16, "bold"))
    header.pack(pady=10)


    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    load_button = tk.Button(button_frame, text="Wczytaj plik", font=("Arial", 12), command=lambda: load_file(output_text))
    load_button.grid(row=0, column=0, padx=5)


    output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier", 10), width=80, height=25)
    output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    root.mainloop()

if __name__ == "__main__":
    create_app()
