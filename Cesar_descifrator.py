from scapy.all import sniff, IP, ICMP
import time

# Almacenar letras recibidas
letras = []
ultimo_paquete = time.time()
TIEMPO_LIMITE = 10  # Segundos sin recibir paquetes antes de terminar

# Diccionario de palabras más amplio (agrega más palabras si es necesario)
diccionario_simulado = {
    "hola", "mundo", "prueba", "mensaje", "secreto", "la", "el", "casa", "gato", "perro",
    "y", "que", "tal", "si", "hago", "esto", "es", "un", "bien", "como", "estamos", "yo",
    "vivo", "en", "mi", "cielo", "tierra", "aire", "agua", "todos", "hacer", "trabajo", "comida"
}

def cesar_descifrar(texto, desplazamiento):
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            resultado += chr((ord(char) - base - desplazamiento) % 26 + base)
        elif char == " ":
            resultado += " "
        else:
            resultado += char
    return resultado

def es_palabra_valida(palabra, diccionario):
    return palabra.lower() in diccionario

def descifrar_y_mostrar():
    texto = "".join(letras)
    print("Posibles descifrados:")
    mejores = []
    max_palabras_validas = 0  # Almacenamos el máximo número de palabras válidas

    # Generamos las posibles combinaciones
    for i in range(26):
        descifrado = cesar_descifrar(texto, i)
        palabras = descifrado.split()
        palabras_validas = sum(1 for p in palabras if es_palabra_valida(p, diccionario_simulado))
        mejores.append((descifrado, palabras_validas))
        max_palabras_validas = max(max_palabras_validas, palabras_validas)

    # Imprimir solo la mejor opción en verde
    for descifrado, score in mejores:
        if score == max_palabras_validas:
            print(f"\033[92m{descifrado}\033[0m (Palabras reconocidas: {score})")  # Resaltamos en verde
        else:
            print(f"{descifrado} (Palabras reconocidas: {score})")  # No resaltamos las otras opciones
    print()

def procesar_paquete(pkt):
    global ultimo_paquete
    if ICMP in pkt and pkt[ICMP].type == 8:  # Echo Request
        identifier = pkt[ICMP].id
        letra = chr(identifier)
        letras.append(letra)
        ultimo_paquete = time.time()  # Reiniciar temporizador
        print(f"Letra recibida: {letra}")  # Imprimir cada letra en tiempo real

print("Escuchando paquetes ICMP tipo 8 (solo solicitudes)...")

# Captura paquetes en segundo plano mientras verificamos el tiempo
while True:
    sniff(filter="icmp", prn=procesar_paquete, store=0, timeout=2)  # Captura por 2 segundos cada vez

    # Si ha pasado el TIEMPO_LIMITE sin nuevos paquetes, terminamos
    if time.time() - ultimo_paquete > TIEMPO_LIMITE:
        print("No se detectaron más paquetes. Finalizando captura...")
        if letras:
            descifrar_y_mostrar()
        else:
            print("No se recibieron datos.")
        break
