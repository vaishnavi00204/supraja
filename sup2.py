import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import numpy as np
import os
import shutil
from cryptography.fernet import Fernet
import smtplib

# Global variables to keep track of the last image path, backup path, and last action
last_image_path = None
backup_image_path = None
last_action = None
key_file_path = None  # Path to save the encryption key file

def generate_key():
    return Fernet.generate_key()

def encode_image(image_path, message, key, output_path):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    img_array = np.array(img)

    encrypted_message += b'\x00'  # Adding delimiter (null character) to mark the end of the message
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)
    message_len = len(binary_message)
    
    if message_len > img_array.size:
        raise ValueError("Message is too long to fit in the image.")

    binary_message_index = 0
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            for k in range(img_array.shape[2]):
                if binary_message_index < message_len:
                    img_array[i, j, k] = (img_array[i, j, k] & ~1) | int(binary_message[binary_message_index])
                    binary_message_index += 1

    encoded_img = Image.fromarray(img_array)
    encoded_img.save(output_path)

def decode_image(image_path, key):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    img_array = np.array(img)

    binary_message = ''
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            for k in range(img_array.shape[2]):
                binary_message += str(img_array[i, j, k] & 1)
    
    byte_message = bytearray()
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        if len(byte) < 8:
            break
        byte_message.append(int(byte, 2))
        if byte_message[-1] == 0:
            break
    
    encrypted_message = bytes(byte_message[:-1])
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_message)
        return decrypted_message.decode()
    except:
        return "Invalid encryption key or corrupted image."

def encode():
    global last_image_path, backup_image_path, last_action, key_file_path
    message = message_entry.get("1.0", tk.END).strip()
    if not message:
        messagebox.showwarning("No Text", "Please provide text to be encoded.")
        return

    image_path = filedialog.askopenfilename(filetypes=[("Image files", ".png;.jpg;*.jpeg")])
    if not image_path:
        return
    last_image_path = image_path
    backup_image_path = f"{os.path.splitext(image_path)[0]}_backup{os.path.splitext(image_path)[1]}"
    shutil.copy(image_path, backup_image_path)
    last_action = 'encode'
    update_image_info(image_path)  # Update image size information
    output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", ".png"), ("JPEG files", ".jpg;*.jpeg")])
    if not output_path:
        return

    key = generate_key()
    key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", ".key")])
    if not key_file_path:
        return
    with open(key_file_path, 'wb') as key_file:
        key_file.write(key)

    try:
        encode_image(image_path, message, key, output_path)
        messagebox.showinfo("Success", f"Image encoded successfully!\nEncryption key saved to: {key_file_path}")
        preview_image(output_path)
        clear_message()  # Clear message after encoding
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decode():
    global last_image_path, backup_image_path, last_action
    image_path = filedialog.askopenfilename(filetypes=[("Image files", ".png;.jpg;*.jpeg")])
    if not image_path:
        return
    last_image_path = image_path
    last_action = 'decode'
    update_image_info(image_path)  # Update image size information
    key_file_path = filedialog.askopenfilename(filetypes=[("Key files", ".key")])
    if not key_file_path:
        return
    with open(key_file_path, 'rb') as key_file:
        key = key_file.read()

    try:
        message = decode_image(image_path, key)
        messagebox.showinfo("Decoded Message", message)
        preview_image(image_path)
        clear_message()  # Clear message after decoding
    except Exception as e:
        messagebox.showerror("Error", str(e))

def open_image():
    global last_image_path, backup_image_path, last_action
    image_path = filedialog.askopenfilename(filetypes=[("Image files", ".png;.jpg;*.jpeg")])
    if not image_path:
        return
    last_image_path = image_path
    backup_image_path = f"{os.path.splitext(image_path)[0]}_backup{os.path.splitext(image_path)[1]}"
    shutil.copy(image_path, backup_image_path)
    last_action = 'open'
    img = Image.open(image_path)
    img.thumbnail((250, 250))
    img = ImageTk.PhotoImage(img)
    lb1.config(image=img)
    lb1.image = img
    update_image_info(image_path)

def save_image():
    if not lb1.image:
        messagebox.showwarning("No Image", "No image to save.")
        return
    image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", ".png"), ("JPEG files", ".jpg;*.jpeg")])
    if not image_path:
        return
    try:
        lb1.image.save(image_path)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def clear_message():
    message_entry.delete("1.0", tk.END)

def update_image_info(image_path):
    img = Image.open(image_path)
    width, height = img.size
    format = img.format
    mode = img.mode
    size_label.config(text=f"Image Size: {width} x {height} pixels\nFormat: {format}\nMode: {mode}")

def preview_image(image_path):
    img = Image.open(image_path)
    img.thumbnail((250, 250))
    img = ImageTk.PhotoImage(img)
    lb1.config(image=img)
    lb1.image = img

def undo_last_operation():
    global last_image_path, backup_image_path, last_action
    if backup_image_path and last_action:
        if os.path.exists(backup_image_path):
            shutil.copy(backup_image_path, last_image_path)
            preview_image(last_image_path)
            update_image_info(last_image_path)
            messagebox.showinfo("Undo", f"Reverted to the last image operation: {last_action}")
            os.remove(backup_image_path)  # Clean up backup file
        else:
            messagebox.showwarning("Undo Error", "No backup image found.")
    else:
        messagebox.showwarning("No Operation", "No previous operation to undo.")

def toggle_stegano_tool():
    if calc_frame.winfo_ismapped():
        calc_frame.pack_forget()
        steganography_frame.pack(padx=10, pady=10)
    else:
        steganography_frame.pack_forget()
        calc_frame.pack(padx=10, pady=10)

def add_digit(digit):
    current = calc_entry.get()
    calc_entry.delete(0, tk.END)
    calc_entry.insert(0, current + str(digit))

def clear_calc():
    calc_entry.delete(0, tk.END)

def evaluate_calc():
    try:
        result = eval(calc_entry.get())
        calc_entry.delete(0, tk.END)
        calc_entry.insert(0, str(result))
    except:
        calc_entry.delete(0, tk.END)
        calc_entry.insert(0, "Error")

root = tk.Tk()
root.title("Calculator")

# Frame for the calculator
calc_frame = tk.Frame(root)

calc_entry = tk.Entry(calc_frame, width=16, font=('Arial', 24), bd=5, insertwidth=2, bg="powder blue", justify='right')
calc_entry.grid(row=0, column=0, columnspan=4)

buttons = [
    ('7', 1, 0), ('8', 1, 1), ('9', 1, 2), ('/', 1, 3),
    ('4', 2, 0), ('5', 2, 1), ('6', 2, 2), ('*', 2, 3),
    ('1', 3, 0), ('2', 3, 1), ('3', 3, 2), ('-', 3, 3),
    ('0', 4, 0), ('C', 4, 1), ('=', 4, 2), ('+', 4, 3)
]

for (text, row, col) in buttons:
    if text == 'C':
        tk.Button(calc_frame, text=text, padx=16, pady=16, font=('Arial', 20, 'bold'), command=clear_calc).grid(row=row, column=col)
    elif text == '=':
        tk.Button(calc_frame, text=text, padx=16, pady=16, font=('Arial', 20, 'bold'), command=evaluate_calc).grid(row=row, column=col)
    else:
        tk.Button(calc_frame, text=text, padx=16, pady=16, font=('Arial', 20, 'bold'), command=lambda t=text: add_digit(t)).grid(row=row, column=col)

# Frame for the steganography tool (hidden initially)
steganography_frame = tk.Frame(root)

tk.Label(steganography_frame, text="Message to Encode:").grid(row=0, column=0, sticky="w")
message_entry = tk.Text(steganography_frame, height=5, width=40)
message_entry.grid(row=1, column=0, columnspan=2, pady=5)

encode_button = tk.Button(steganography_frame, text="Encode Image", command=encode)
encode_button.grid(row=2, column=0, pady=5)

decode_button = tk.Button(steganography_frame, text="Decode Image", command=decode)
decode_button.grid(row=2, column=1, pady=5)

open_button = tk.Button(steganography_frame, text="Open Image", command=open_image)
open_button.grid(row=3, column=0, pady=5)

save_button = tk.Button(steganography_frame, text="Save Image", command=save_image)
save_button.grid(row=3, column=1, pady=5)

clear_button = tk.Button(steganography_frame, text="Clear Message", command=clear_message)
clear_button.grid(row=4, column=0, pady=5)

undo_button = tk.Button(steganography_frame, text="Undo Encode", command=undo_last_operation)
undo_button.grid(row=4, column=1, pady=5)

size_label = tk.Label(steganography_frame, text="Image Size:")
size_label.grid(row=6, column=0, columnspan=2, pady=5)

lb1 = tk.Label(steganography_frame)
lb1.grid(row=7, column=0, columnspan=2, pady=10)

# Switch between calculator and steganography tool using F12
root.bind('<F12>', lambda event: toggle_stegano_tool())

# Start with the calculator interface
calc_frame.pack(padx=10, pady=10)

root.mainloop()
