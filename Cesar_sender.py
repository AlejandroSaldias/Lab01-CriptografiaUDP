import socket
import struct
import time

# Función para calcular checksum de ICMP
def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

# Función para enviar paquetes ICMP con letras cifradas
def send_icmp_packets(destination="8.8.8.8"):
    """Lee el mensaje cifrado de un archivo y lo envía en paquetes ICMP."""
    try:
        with open("mensaje_cifrado.txt", "r", encoding="utf-8") as file:
            encrypted_text = file.read().strip()
    except FileNotFoundError:
        print("Error: No se encontró el archivo mensaje_cifrado.txt")
        return

    print(f"Texto cifrado a enviar: {encrypted_text}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    for letter in encrypted_text:
        identifier = ord(letter)  # Convierte la letra en un número ASCII

        header = struct.pack("!BBHHH", 8, 0, 0, identifier, 1)  # Tipo, código, checksum, ID, secuencia
        my_checksum = checksum(header)
        header = struct.pack("!BBHHH", 8, 0, my_checksum, identifier, 1)
        packet = header

        print(f"Enviando letra '{letter}' como identificador {identifier}")
        sock.sendto(packet, (destination, 1))

        time.sleep(0.5)  # Pausa para evitar detección

    sock.close()
    print("Mensajes enviados correctamente.")

if __name__ == "__main__":
    send_icmp_packets()
