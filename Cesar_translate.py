import unicodedata

def get_shift_base(char: str) -> int:
    return ord('A') if char.isupper() else ord('a')

def normalize_char(char):
    nfkd_form = unicodedata.normalize('NFKD', char)
    return nfkd_form[0] if nfkd_form and nfkd_form[0].isalpha() else char

def cesar_cipher(text, shift):
    shift %= 26  # Evitar desplazamientos mayores a 26
    encrypted_text = ""
    for char in text:
        char = normalize_char(char)
        if char.isalpha() or char == " ":  # Solo letras y espacios
            if char.isalpha():
                shift_base = get_shift_base(char)
                encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            else:
                encrypted_text += char  # Mantener espacios
        else:
            raise ValueError("El texto solo puede contener letras y espacios.")
    return encrypted_text

if __name__ == "__main__":
    texto = input("Ingrese el texto a cifrar: ")
    desplazamiento = int(input("Ingrese el número de desplazamiento: "))

    try:
        mensaje_cifrado = cesar_cipher(texto, desplazamiento)
        print(f"Texto cifrado: {mensaje_cifrado}")

        # Guardar en un archivo para que el otro programa lo use
        with open("mensaje_cifrado.txt", "w", encoding="utf-8") as file:
            file.write(mensaje_cifrado)

        print("Mensaje cifrado guardado en mensaje_cifrado.txt")

    except ValueError as e:
        print(f"Error: {e}")
