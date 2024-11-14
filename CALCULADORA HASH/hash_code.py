import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

def calcular_hash_arquivo(caminho_arquivo, algoritmo='sha256'):
    hash_func = hashlib.new(algoritmo)
    with open(caminho_arquivo, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hash_func.update(byte_block)
    return hash_func.hexdigest()

def selecionar_arquivo():
    caminho_arquivo = filedialog.askopenfilename()
    if caminho_arquivo:
        hash_arquivo = calcular_hash_arquivo(caminho_arquivo, algoritmo_var.get())
        resultado_var.set(f"Hash ({algoritmo_var.get()}): {hash_arquivo}")
        copiar_botao.config(state=tk.NORMAL)

def copiar_hash():
    root.clipboard_clear()
    root.clipboard_append(resultado_var.get())
    messagebox.showinfo("Informação", "Hash copiado para a área de transferência!")

# Configurações da janela principal
root = tk.Tk()
root.title("Calculadora de Hash de Arquivo")

# Variáveis
algoritmo_var = tk.StringVar(value='sha256')
resultado_var = tk.StringVar()

# Elementos da interface
frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

label_algoritmo = tk.Label(frame, text="Algoritmo:")
label_algoritmo.grid(row=0, column=0, padx=5, pady=5, sticky="e")

opcoes_algoritmo = ['md5', 'sha1', 'sha256', 'sha512']
menu_algoritmo = tk.OptionMenu(frame, algoritmo_var, *opcoes_algoritmo)
menu_algoritmo.grid(row=0, column=1, padx=5, pady=5)

botao_selecionar = tk.Button(frame, text="Selecionar Arquivo", command=selecionar_arquivo)
botao_selecionar.grid(row=1, column=0, columnspan=2, pady=10)

label_resultado = tk.Label(frame, textvariable=resultado_var, wraplength=400)
label_resultado.grid(row=2, column=0, columnspan=2, pady=10)

copiar_botao = tk.Button(frame, text="Copiar Hash", command=copiar_hash, state=tk.DISABLED)
copiar_botao.grid(row=3, column=0, columnspan=2, pady=10)

# Iniciar o loop da interface
root.mainloop()
