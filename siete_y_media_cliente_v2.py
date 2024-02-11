import socket
import sys

#importación para la encriptación y la desencriptación de los mensajes.
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 5000
socket_cliente = None

def conexion_cliente():
    """Función donde creamos el socket."""
    global socket_cliente
    try:
        socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Socket del cliente creado")
    except socket.error:
        print("Fallo en la creación del socket cliente.")
        sys.exit()

    socket_cliente.connect((HOST, PORT))

def recibir_info():
    """Función para recibir la información del servidor y la devuelve desencriptada."""
    msg_encript = socket_cliente.recv(1024)
    return desencriptar_datos(msg_encript).decode("utf-8")

def enviar_info(msg):
    """Función para enviar la información al servidor encriptada"""
    socket_cliente.sendall(encriptar_mensaje(msg))

def encriptar_mensaje(msg):
    """Función que nos encripta los datos que enviamos al servidor """
    try:
        #Cargar la clave pública del servidor
        fichero_path = Path(__file__).parent / "publica_servidor_sieteymedia.pem"
        with open(fichero_path) as file:
            recipient_key = RSA.import_key(file.read())

        #Generar una clave de sesión aleatorio 
        session_key = get_random_bytes(16)

        #Cifrar el mensaje pasado a binario con AES
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        cipher_text, tag = cipher_aes.encrypt_and_digest(msg.encode("utf-8"))

        #cifrar la clave de sesion con RSA
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        #Combinar los componentes cifrados en un mensaje cifrado
        msg_encript = enc_session_key+cipher_aes.nonce+tag+cipher_text

        return msg_encript
    except Exception as e:
        print(f"Error al cifrar datos: {e}")
        return None

def desencriptar_datos(msg_encript):
    """Función que nos desencripta los datos que enviamos al servidor"""
    try:
        #Cargar la clave privada del usuario
        fichero_path = Path(__file__).parent / "privada_usuarioA_sieteymedia.pem"
        with open(fichero_path, 'r') as file:
            private_key = RSA.import_key(file.read())
        key_size = private_key.size_in_bytes()

        #Separar los componentes cifrados del mensaje
        enc_session_key = msg_encript[:key_size]
        nonce = msg_encript[key_size:key_size+16]
        tag = msg_encript[key_size+16: key_size+32]
        cipher_text = msg_encript[key_size+32:]

        #Descifrar la clave de sesión con RSA
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        #Descifrar el mensaje con la clave de sesión
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        msg_desenc = cipher_aes.decrypt_and_verify(cipher_text, tag)

        return msg_desenc
    except Exception as e:
        print(f"Error al desencriptar el mensaje: {e}")
        return None

def ver_menu():
    """La función ver_menu es la salida del menu por pantalla para poder elegir, una vez introducida la opción que deseamos,
    Nos redirije a la función correspondiente."""
    try:
        salida = False

        while not salida:
            print("""
                        7 Y MEDIO
        ***************************************
            1 - JUGAR PARTIDA
            2 - RESUMEN PARTIDA
            3 - SALIR DEL JUEGO
        ***************************************
                    """)
            opcion = opcion_elegida()
            if opcion == 1:
                enviar_info(str(opcion))
                jugar_partida()
                adios_partida()
            elif opcion == 2:
                enviar_info(str(opcion))
                resumen_partida()
            elif opcion == 3:
                enviar_info(str(opcion))
                print("\nGracias por jugar conmigo, espero volver a verte.\n")
                salida = True
    finally:
        socket_cliente.close()

def opcion_elegida():
    """Esta función es para controlar que lo que entre por pantalla sea lo que se pide, en este caso un número del 1 al 3
    dependiendo de lo que queramos hacer."""
    valido = False

    while not valido:
        try:
            opcion = int(input("Dime tu elección: \n"))
            if 0 < opcion < 4:
                valido = True
            else:
                print("Opción no válida, introduzca un número del 1 al 3")
        except ValueError:
            print(f"Opción no válida, introduzca un número del 1 al 3")
    return opcion

def jugar_partida():
    control = False
    while not control:
        mensaje = recibir_info().split('|') 
        print(mensaje[0]) 
        if mensaje[1]=='True':
            nueva2 = nueva_jugada()
            if nueva2 == "n":
                control = True
        if mensaje[1]=='False':
            mensaje[1] = 1
            enviar_info(str(1))
            control = True
            
def nueva_jugada():
    control = False
    while not control:
        try:
            respuesta = input("""
                        \n¿Quieres una carta más?
                                    Si --> s
                                    No --> n\n
                                        """).lower()
            if respuesta =="n" or respuesta =="s":
                enviar_info(str(respuesta))
                control = True
            else:
                print("Opción no válida")
        except Exception as e:
            print(f"Error: {e}.Por favor introduzca una respuesta válida n / s")
    return respuesta
    
def adios_partida():

   print(recibir_info())
   

def resumen_partida():
    mensaje1 = recibir_info()
    print("""
            *-*-*-*-*-*-*-*-*-*-*-*-*
                RESUMEN DE PARTIDAS
            *-*-*-*-*-*-*-*-*-*-*-*-*
            """)
    print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*")
    if mensaje1 == "p":
        print("      No se ha jugado ninguna partida aún.")        
    elif mensaje1 != "p":
        print(mensaje1)
    print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*")    
    presiona_tecla()

def presiona_tecla():
    """Esta función nos sirve para que se mantenga el resumen en pantalla."""
    input(f"\nPor favor, presiona ENTER para seguir.\n")

if __name__=="__main__":

    conexion_cliente()
    print("""
          *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
            Bienvenid@ al juego 7 y medio
          *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
          """)
    ver_menu()

