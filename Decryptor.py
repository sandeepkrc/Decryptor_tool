from Crypto.Cipher import PKCS1_OAEP,AES
from Crypto.PublicKey import RSA
from Crypto.Signature.pss import MGF1
from Crypto.Hash import SHA256,SHA1
import os
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.button import Button



class DecryptApp(App):
    def build(self):

        # Create the main layout for the app
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Input field for plain text
        self.input_text = TextInput(hint_text="Enter text to encrypt", multiline=False, font_size=20)

        # Label to show the encrypted result
        self.encrypted_label = Label(text="Encrypted Text: ", font_size=20)

        # Button to trigger encryption
        encrypt_button = Button(text="Encrypt", font_size=20)
        encrypt_button.bind(on_press=self.encrypt_text)





        # Label to show the decrypted result
        self.enc_text = TextInput(hint_text="Enter text to Decrypt", multiline=False, font_size=20)
        
        self.decrypted_label = Label(text="Decrypted Text: ", font_size=20)

        # Button to trigger decryption
        decrypt_button = Button(text="Decrypt", font_size=20)
        decrypt_button.bind(on_press=self.decrypt_text)

        # Add widgets to the layout
        layout.add_widget(self.input_text)
        layout.add_widget(encrypt_button)
        layout.add_widget(self.encrypted_label)

        layout.add_widget(self.enc_text)#
        layout.add_widget(decrypt_button)
        layout.add_widget(self.decrypted_label)

        return layout

    def encrypt_text(self, instance):
        # Get the plain text from the input
        plain_text = self.input_text.text
        rsa_manager = RSAManager()

        # Encrypt the message
        encrypted_message = rsa_manager.encrypt_message(plain_text)
        print("=======",encrypted_message)
        self.encrypted_label.text = f"Encrypted Text: {encrypted_message}"

        # Store the encrypted message for decryption later
        self.encrypted_message = encrypted_message

    def decrypt_text(self, instance):
        try:
        # Get the encrypted message stored during encryption
            rsa_manager = RSAManager()

        # Decrypt the message
            decrypted_message = rsa_manager.decrypt_message(self.encrypted_message)
            self.decrypted_label.text = f"Decrypted Text: {decrypted_message}"
        except Exception as e:
            print(str(e))

#######################333
# FILE


from Crypto.PublicKey import RSA

class RSAKeyPair:
    """Class responsible for generating RSA key pairs and exporting to .crt and .key formats."""
    
    def __init__(self, key_size: int = 2048):
        self.key = RSA.generate(key_size)
        self.public_key = self.key.publickey()
        self.private_key = self.key

    def get_public_key(self):
        """Exports public key in PEM format."""
        return self.public_key.export_key('PEM')

    def get_private_key(self):
        """Exports private key in PEM format."""
        return self.private_key.export_key('PEM')

    def save_public_key_to_crt(self, filename: str):
        """Saves the public key to a .crt file."""
        with open(filename, 'wb') as f:
            f.write(self.get_public_key())

    def save_private_key_to_key(self, filename: str):
        """Saves the private key to a .key file."""
        with open(filename, 'wb') as f:
            f.write(self.get_private_key())

# # Instantiate RSAKeyPair
# n = RSAKeyPair()

# # Save public key to .crt and private key to .key
# n.save_public_key_to_crt("public_key.crt")
# n.save_private_key_to_key("private_key.key")

# print("Public key saved as public_key.crt")
# print("Private key saved as private_key.key")






class RSAEncryption:
    """
    Class responsible for encrypting data using RSA.
    """
    def __init__(self,path=None):
        self.path=None
     
    def encrypt(self, message: str) -> bytes:
        """
        Encrypts a message using the public key.
        """
        try:
            print("----22222---------", os.getcwd())
            abs_path = os.getcwd()+'/public_key.crt'
            with open(abs_path, 'rb') as f:
                public_key = RSA.import_key(f.read())

            message_bytes = message.encode('utf-8')
            cipher = PKCS1_OAEP.new(key =public_key,hashAlgo=SHA256,mgfunc=lambda x,y: MGF1(x,y,SHA1))
            encrypted_message = cipher.encrypt(message_bytes)
            print("---",encrypted_message)          
            return encrypted_message
        except Exception as e:
            print(str(e),"===========<><")


class RSADecryption:
    """
    Class responsible for decrypting data using RSA.
    """
    
    def __init__(self,path=None):
        self.path=None
     
    

    def decrypt(self, encrypted_message: bytes) -> str:
        """Decrypts a message using the private key."""
        try:
            abs_path = os.getcwd() +'/private_key.key'
            with open(abs_path, 'rb') as f:
                private_key = RSA.import_key(f.read())
            cipher = PKCS1_OAEP.new(key=private_key, hashAlgo=SHA256, mgfunc=lambda x, y: MGF1(x, y, SHA1))
            decrypted_message = cipher.decrypt(encrypted_message)
            return decrypted_message.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return ''





class RSAManager:
    """Manager class for handling RSA operations."""
    
    def __init__(self, key_size: int = 2048):
        self.key_pair = RSAKeyPair(key_size)
        self.encryption = RSAEncryption(path=None)
        self.decryption = RSADecryption(path=None)

    def encrypt_message(self, message: str) -> bytes:
        return self.encryption.encrypt(message)

    def decrypt_message(self, encrypted_message: bytes) -> str:
        return self.decryption.decrypt(encrypted_message)


# Run the app
if __name__ == '__main__':

    # # Instantiate RSAKeyPair
    n = RSAKeyPair()
    # Save public key to .crt and private key to .key
    n.save_public_key_to_crt("public_key.crt")
    n.save_private_key_to_key("private_key.key")
    DecryptApp().run()



# # Example Usage
# if __name__ == "__main__":
#     rsa_manager = RSAManager()

#     # Encrypting a message
#     message = "Hello, this is a secret message."
#     encrypted_message = rsa_manager.encrypt_message(message)
#     print(f"Encrypted message: {encrypted_message}")

#     # # Decrypting the message
#     decrypted_message = rsa_manager.decrypt_message(encrypted_message)
#     print(f"Decrypted message: {decrypted_message}")