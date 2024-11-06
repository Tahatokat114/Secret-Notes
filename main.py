from email.errors import MessageError
from tkinter import *
from PIL import Image,ImageTk
from cryptography.fernet import Fernet
import os
import base64
from tkinter import messagebox

masaustuyolu = os.path.join(os.path.expanduser("~"),"Desktop","Secret Notes")
# Kullanıcının master key'ini Fernet key formatına dönüştürme
def generate_fernet_key(user_key):
    padded_key = user_key.ljust(32)[:32]  # Master key'i 32 karaktere tamamla
    return base64.urlsafe_b64encode(padded_key.encode())  # Base64 formatına çevir

#Şifreleme fonksiyonu
def encrypt():
    title = title_entry.get().strip()
    secret = secret_text.get("1.0", END).strip()
    master_key = master_entry.get().strip()

    if not title or not secret or not master_key:
        messagebox.showwarning("HATA!","Tüm alanlar doldurulmalıdır!")
        print("Tüm alanlar doldurulmalıdır!")
        return

    try:
        # Şifreleme anahtarını oluştur
        fernet_key = generate_fernet_key(master_key)
        cipher_suite = Fernet(fernet_key)
        encrypted_secret = cipher_suite.encrypt(secret.encode())

        # Dosya oluştur ve kaydet
        file_path = os.path.join(masaustuyolu, f"{title}.txt")
        with open(file_path, "w") as file:
            file.write(f"Title: {title}\n")
            file.write(f"Encrypted Secret: {encrypted_secret.decode()}\n")



        print(f"Gizli not '{file_path}' adresine kaydedildi.")

        # Tüm alanları temizle
        title_entry.delete(0, END)
        secret_text.delete("1.0", END)
        master_entry.delete(0, END)

    except Exception as e:
        messagebox.showwarning("HATA!","Şifreleme sırasında bir hata oluştu")
        print("Şifreleme sırasında bir hata oluştu:", str(e))

# Şifre çözme fonksiyonu
def decrypt():
    encrypted_text = secret_text.get("1.0", END).strip()
    master_key = master_entry.get().strip()

    if not master_key or not encrypted_text:
        messagebox.showwarning("HATA!","Master key ve şifreli veri girilmelidir!")
        print("Master key ve şifreli veri girilmelidir!")
        return

    try:
        # Şifreleme anahtarını oluştur
        fernet_key = generate_fernet_key(master_key)
        cipher_suite = Fernet(fernet_key)
        decrypted_secret = cipher_suite.decrypt(encrypted_text.encode()).decode()
        print("Çözülen Not:", decrypted_secret)

    except Exception as e:
        messagebox.showwarning("HATA!","Şifre çözme başarısız")
        print("Şifre çözme başarısız:", str(e))


pencere = Tk()
pencere.title("Secret Notes")
pencere.config(bg="light gray")
pencere.geometry("300x700+550+80")
foto_yolu = "secret.jpg"
foto = Image.open(foto_yolu)
resizedimage= foto.resize((200,100))
photo = ImageTk.PhotoImage(resizedimage)

photolabel = Label(pencere,image=photo)
photolabel.pack(pady=20)


title_label= Label(pencere,text="Enter your title",bg="light gray",fg="black")
title_label.place(x=100 , y=150)

title_entry  =Entry(pencere,width=20)
title_entry.focus()
title_entry.place(x=55 , y=175)

secret_label =  Label(pencere,text="Enter your secret",bg="light gray",fg="black")
secret_label.place(x=96 , y=210)

secret_text = Text(pencere,width=30,height=15)
secret_text.place(x=45, y=235)

master_label= Label(pencere,text="Enter master key",bg="light gray",fg="black")
master_label.place(x=100 , y=450)

master_entry =Entry(pencere,width=20)
master_entry.place(x=55 , y=475)

save_encrypt_button = Button(pencere, text="Save & Encrypt",width=10,font="arial 10 normal",command=encrypt)
save_encrypt_button.place(x=105 , y=520)

decrypt_button = Button(pencere, text="Decrypt",width=10,font="arial 10 normal",command=decrypt)
decrypt_button.place(x=105 , y=550)

pencere.mainloop()







#