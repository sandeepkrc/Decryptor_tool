import os
import threading
from zipfile import ZipFile
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.progressbar import ProgressBar
from kivy.uix.popup import Popup
from kivy.core.window import Window
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256, SHA1
from kivy.clock import Clock  # Import Clock for scheduling UI updates
from kivy.graphics import Color, RoundedRectangle
from Crypto.Signature.pss import MGF1

# def process_file(self, instance):
#     # Get the selected file
#     selected_file = self.filechooser.selection
#     # Get the selected private file
#     selected_private_file = self.private_filechooser.selection

#     if selected_file and selected_private_file:
#         file_path = selected_file[0]
#         private_file_path = selected_private_file[0]
#         if file_path.endswith('.zip'):  # Validate file type for the main file
#             self.selected_file_label.text = f"Selected File: {file_path}"
#             if private_file_path.endswith('.key'):  # Assuming the private file should have a .key extension
#                 self.private_file_label.text = f"Selected Private File: {private_file_path}"


#                 # Start the decryption process in a new thread
#                 threading.Thread(target=self.decrypt_file, args=(file_path,), daemon=True).start()
#             else:
#                 self.show_popup("Invalid Private File", "Please select a valid private file (.key)")
#         else:
#             self.show_popup("Invalid Main File", "Please select a valid zip file (.zip)")
#     else:
#         missing_files = []
#         if not selected_file:
#             missing_files.append("main file")
#         if not selected_private_file:
#             missing_files.append("private file")
#         self.show_popup("Files Required", f"Please select a {' and '.join(missing_files)} to decrypt.")
#         print("Missing files:", ", ".join(missing_files))
class RSAEncryption:
    """
    Class responsible for encrypting data using RSA.
    """

    def __init__(self, public_key_path):

        self.public_key_path = public_key_path

    def encrypt(self, message: str) -> bytes:
        """
        Encrypts a message using the public key.
        """
        try:
            with open(self.public_key_path, "rb") as f:
                public_key = RSA.import_key(f.read())

            message_bytes = message.encode("utf-8")
            cipher = PKCS1_OAEP.new(
                key=public_key, hashAlgo=SHA256, mgfunc=lambda x, y: MGF1(x, y, SHA1)
            )
            encrypted_message = cipher.encrypt(message_bytes)
            print("---", encrypted_message)
            return encrypted_message
        except Exception as e:
            print(str(e), "===========<><")
        ############################################

    def encrypt(self, data):
        """ encrypting a message using RSA encryption
        (public key)
        """

        path = "componen"
        new_path = path + "/" + "public.crt"
        abs_path = os.path.abspath(new_path)
        with open(abs_path, "rb") as f:
            public_key = RSA.import_key(f.read())
            chunk_size = 190
            chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
        cipher = PKCS1_OAEP.new(
            key=public_key, hashAlgo=SHA256, mgfunc=lambda x, y: MGF1(x, y, SHA1)
        )
        byte_array = bytearray()
        for chunk in chunks:
            msg = cipher.encrypt(chunk)
            byte_array_data = bytearray(msg)
            byte_array += byte_array_data
        return byte_array


class RSADecryption:
    """
    Class responsible for decrypting data using RSA.
    """

    def __init__(self, private_key_path):

        self.private_key_path = private_key_path

    def decrypt(self, encrypted_message: bytes) -> str:
        """
        Decrypts a message using the private key.
        """
        try:

            with open(self.private_key_path, "rb") as f:
                private_key = RSA.import_key(f.read())
            cipher = PKCS1_OAEP.new(
                key=private_key, hashAlgo=SHA256, mgfunc=lambda x, y: MGF1(x, y, SHA1)
            )
            decrypted_message = cipher.decrypt(encrypted_message)
            return decrypted_message.decode("utf-8")
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return ""


def decrypt_logfile(file_to_decrypt, update_progress, private_key_path):
    """
    Decrypt the file and save in the same directory,
    then delete the old (encrypted) file.
    """
    original_dir = os.path.dirname(file_to_decrypt)
    original_filename = os.path.basename(file_to_decrypt)
    decrypted_filename = os.path.splitext(original_filename)[0] + "_decrypted.log"
    decrypted_file_path = os.path.join(original_dir, decrypted_filename)

    with open(file_to_decrypt, "rb") as dec:
        data = dec.read()
        chunk_size = 256
        chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
        total_chunks = len(chunks)

        with open(decrypted_file_path, "w") as f:
            for i, chunk in enumerate(chunks):
                rsa_manager = RSADecryption(private_key_path)
                decrypted_message = rsa_manager.decrypt(chunk)
                f.write(decrypted_message + "\n")

                # Update progress
                progress = (i + 1) / total_chunks * 100
                update_progress(progress)

    os.remove(file_to_decrypt)
    return None


def unzip(zip_path, update_progress, private_key_path):
    """
    Function to unzip a zip file into a new directory.
    :param zip_path: Path to a zip file which will be unzipped.
    """
    decrypted_logs = os.path.join(os.getcwd(), "Decrypted_logs")
    os.makedirs(decrypted_logs, exist_ok=True)

    with ZipFile(zip_path, "r") as zObject:
        zObject.extractall(decrypted_logs)
        extracted_files = zObject.namelist()

    total_files = len(extracted_files)
    for i, file in enumerate(extracted_files):
        extracted_file_path = os.path.join(decrypted_logs, file)
        if file.endswith(".zip"):
            unzip(extracted_file_path, update_progress, private_key_path)
            os.remove(extracted_file_path)

        decrypt_logfile(extracted_file_path, update_progress, private_key_path)

        # Update progress for unzipping
        progress = (i + 1) / total_files * 100
        update_progress(progress)

    return decrypted_logs


class RoundedButton(Button):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(size=self._update_rect, pos=self._update_rect)

    def _update_rect(self, *args):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*self.background_color)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[15])


class DecryptApp(App):

    def build(self):

        Window.clearcolor = (0.16, 0.16, 0.16, 1)  # Dark gray background
        # Create the main layout for the app
        layout = BoxLayout(orientation="vertical", padding=20, spacing=20)

        # Header label
        header_label = Label(text="Decryption Tool", font_size=32, color=(1, 1, 1, 1))
        layout.add_widget(header_label)

        # FileChooser for selecting a file
        self.filechooser = FileChooserListView(size_hint_y=2)
        layout.add_widget(self.filechooser)

        # Label to display the selected file
        self.selected_file_label = Label(
            text="No file selected", font_size=20, color=(1, 1, 1, 1)
        )
        layout.add_widget(self.selected_file_label)

        # ProgressBar to show decryption progress
        self.progress_bar = ProgressBar(max=100, size_hint_y=0.1)
        layout.add_widget(self.progress_bar)

        # Custom 'Process File' button

        # Button to process the file
        process_file_button = RoundedButton(
            text="Decrypt File", font_size=20, background_color=(0.1, 0.5, 0.8, 1)
        )
        process_file_button.bind(on_press=self.process_file)
        layout.add_widget(process_file_button)

        # FileChooser for selecting the private file
        self.private_filechooser = FileChooserListView(size_hint_y=2)
        layout.add_widget(self.private_filechooser)

        # Label to display the selected private file
        self.private_file_label = Label(
            text="No private file selected", font_size=20, color=(1, 1, 1, 1)
        )
        layout.add_widget(self.private_file_label)

        return layout

    def decrypt_file(self, file_path, private_key_path):

        output_dir = unzip(file_path, self.update_progress, private_key_path)

        self.update_progress(100)  # Set progress to 100% after completion
        print(f"Processing file completed: {file_path}")

        # Schedule to show the popup on the main Kivy thread
        Clock.schedule_once(
            lambda dt: self.show_popup(
                "Decryption Complete",
                f"File has been decrypted successfully:\n{file_path}",
            ),
            0,
        )
        # Reset the selected file label after completion
        Clock.schedule_once(lambda dt: self.reset_selected_file_label(), 0)

        return output_dir

    def process_file(self, instance):
        # Get the selected file
        selected_file = self.filechooser.selection
        print("==", selected_file)
        # Get the selected private file
        selected_private_file = self.private_filechooser.selection
        print("selected_private_file=====", selected_private_file)

        if selected_file and selected_private_file:
            file_path = selected_file[0]
            private_file_path = selected_private_file[0]
            self.selected_file_label.text = f"Selected File: {file_path}"
            self.private_file_label.text = f"Selected Private File: {private_file_path}"

            # Start the decryption process in a new thread
            threading.Thread(
                target=self.decrypt_file,
                args=(file_path, private_file_path),
                daemon=True,
            ).start()
        else:
            missing_files = []
            if not selected_file:
                missing_files.append("main file")
            if not selected_private_file:
                missing_files.append("private file")
            self.show_popup(
                "Files Required",
                f"Please select a {' and '.join(missing_files)} to decrypt.",
            )
            print("Missing files:", ", ".join(missing_files))

    def update_progress(self, progress):
        self.progress_bar.value = progress

    def reset_selected_file_label(self):
        self.selected_file_label.text = "No file selected"
        self.private_file_label.text = (
            "No private file selected"  # Reset private file label
        )

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(0.7, 0.4))
        popup.open()


if __name__ == "__main__":
    DecryptApp().run()
