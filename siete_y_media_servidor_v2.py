from collections.abc import Callable, Iterable, Mapping
import random
import socket
import sys
import threading
from typing import Any

#importación para la encriptación y la desencriptación de los mensajes.
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

global key_size
global private_key
global recipient_key

class Jugador(threading.Thread):
    """Declaramos la clase jugador"""

    def __init__(self, socket_jugador, addr_jugador, nombre_jugador, key_size, private_key, recipient_key):
        super().__init__()
        self.socket_jugador = socket_jugador
        self.direccion = addr_jugador
        self.nombre_jugador = nombre_jugador
        self.puntuacion=0
        self.cerrar = False
        self.ganador = []
        self.key_size = key_size
        self.private_key = private_key
        self.recipient_key = recipient_key

    def run(self):
        #opcion que recogemos del cliente.
        opcion = None 
        with self.socket_jugador:

            print(f"Se ha realizado la conexión con el cliente {self.direccion} con el nombre {self.nombre_jugador}")
            while not self.cerrar:
                try:
                    opcion = int(self.recibir_info())#aqui es donde se recibe la opción del usuario.
                except ValueError:
                    print("Error: Opción inválida, el cliente no envío ningún número.\n")    
                    continue
                print("menu de nuevo")
                if opcion == 1:
                    print(f"el {self.nombre_jugador} ha elegido jugar partida.\n")
                    self.jugar_partida()
                    self.adios_partida()
                    print(f"El {self.nombre_jugador} ha terminado partida.\n")
                elif opcion == 2:
                    print(f"El {self.nombre_jugador} quiere imprimir partida.\n")
                    self.resumen_partida()
                elif opcion == 3:
                    print(f"\nGracias por jugar conmigo, espero volver a verte.\n")
                    self.cerrar = True
            
        self.socket_jugador.close()

    def jugar_partida(self):
        """Esta función nos realiza un random para elegir una 'carta' y en el caso de que sea el 10, 11 u 12,
        estas valdrán 0.5 puntos, el resto tendrán como valor el número que sale. Luego hace una selección a la función que tiene que,
        dependiendo del valor de la global jugador que es la suma total de las jugadas."""

        print(f"{self.nombre_jugador} inicia partida.\n")
        print(f" puntuacion anterior{self.puntuacion}.\n")
        self.puntuacion = 0
        print(f" puntuacion reseteada{self.puntuacion}.\n")

        control = False
        while not control and self.puntuacion < 7.5:
            jugada = random.choice([1, 2, 3, 4, 5, 6, 7, 10, 11, 12])
            if jugada == 10 or jugada == 11 or jugada == 12:
                jugada = 0.5
            self.puntuacion += jugada

            informacion=f"""
                    \n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
                                 CARTAS EN LA MESA                   
                      *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
                        El croupier te da tu carta, es un {jugada}
                        En total de tus jugadas es {self.puntuacion}
                      *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n
            """
            
            if self.puntuacion >= 7.5:
                informacion+="|False"
                self.enviar_info(informacion)
                recibir = self.recibir_info()
                if recibir == 1:
                    control = True
            elif self.puntuacion < 7.5:
                informacion+="|True"
                self.enviar_info(informacion)
                respuesta = self.nueva_jugada()
                if respuesta == "n":
                    control = True
                    
            
            
    def nueva_jugada(self):
        """Esta función lo que hace es preguntar al usuario si desea una nueva carta o no, dependiendo de la respuesta,
        nos llevará a una función u otra.""" 

        print(f"El {self.nombre_jugador} esta eligiendo si quiere carta en nueva_jugada.\n")

        respuesta = self.recibir_info()
        if respuesta == "n":
            print(f"El {self.nombre_jugador} ha elegido que no quiere más cartas.\n")
            return respuesta
        elif respuesta == "s":
            print(f"El {self.nombre_jugador} ha elegido que si quiere más cartas.\n")
            return respuesta
                


    def adios_partida(self):
        """Esta función es para determinar que ha ocurrido en el juego y dependiendo de la variable jugador nos dará un resultado u otro.
        Además, hay creada la variable ganador para guardar la información de cada partida."""  

        print(f"el {self.nombre_jugador} esta en la función adios_partida.\n")

        if self.puntuacion <= 6:
            final =(f"¿En serio te has plantado con {self.puntuacion} puntos? Menudo rajadoooooo")
            self.ganador.append(f"Rajaooooooooo -> {self.puntuacion}")
        elif 6 < self.puntuacion < 7.5:
            final =(f"No está mal, pero el que no arriesga no gana, te quedas con {self.puntuacion} puntos, muy cerca")
            self.ganador.append(f"pichi-picha -> {self.puntuacion}")
        elif self.puntuacion == 7.5:
            final =(f"Eres un gran jugador, ¡¡¡¡Has ganado!!!!")
            self.ganador.append(f"Maquinaaaaaaaaaaa -> {self.puntuacion}")
        elif self.puntuacion > 7.5:
            final = ("Mal jugado, ¡¡¡¡Has perdido!!!!")
            self.ganador.append(f"Loser -> {self.puntuacion}")

        self.enviar_info(str(final))
        

    def resumen_partida(self):
        """Esta función nos imprime el resultado de todas las partidas realizadas."""

        print(f"El {self.nombre_jugador} esta imprimiendo el resumen de partidas.\n")
        print("contenido de self ganado ", self.ganador)
        if not self.ganador :
            mensaje1 = "p"
        else:
            mensaje1 =""
            for i, partida in enumerate(self.ganador):
                mensaje1+=f"Partida {i+1}: {partida}\n"
        self.enviar_info(mensaje1)
        print("mensaje enviado")

    def recibir_info(self):
        """Con esta función recibimos la información del cliente y la desencriptamos"""
        msg_encript = self.socket_jugador.recv(1024)
        msg_desenc = desencriptar_datos(msg_encript, private_key, key_size)
        if msg_desenc is not None:
            return msg_desenc.decode("utf-8")
        else:
            print("Error al desencriptar el mensaje.")
            return ""

    def enviar_info(self, msg):
        """Con esta función enviamos al información al cliente"""
        try:
            msg_encript = encriptar_mensaje(msg.encode(), self.recipient_key)
            self.socket_jugador.sendall(msg_encript)
        except AttributeError as e:
            print(f"Error al enviar información: {e}")
            print(f"msg: {msg}")

def encriptar_mensaje(msg, recipient_key):
    """Función que nos encripta los mensajes que enviamos al cliente"""
    try:
        #Generar una clave de sesión aleatoria
        session_key = get_random_bytes(16)

        #Cifrar el mensaje pasado a binario con AES
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        cipher_text, tag = cipher_aes.encrypt_and_digest(msg)

        #cifrar la clave de sesión con RSA
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        #Combinar los componentes cifrados en un mensaje cifrado
        msg_encript = enc_session_key+cipher_aes.nonce+tag+cipher_text

        print(msg_encript)
        return msg_encript
    except Exception as e:
        print(f"Error al cifrar datos: {e}")
        return None

def desencriptar_datos( msg_encript, private_key, key_size):
    try:
        #Separar los componentes cifrados del mensaje
        enc_session_key = msg_encript[:key_size]
        nonce = msg_encript[key_size:key_size+16]
        tag = msg_encript[key_size+16:key_size+32]
        cipher_text = msg_encript[key_size+32:]

        #Descrifrar la clave de sesión con RSA
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        #Descifrar el mensaje con la clave de sesion
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        msg_desenc = cipher_aes.decrypt_and_verify(cipher_text, tag)

        return msg_desenc
    except Exception as e:
        print(f"Error al desencriptar el mensaje: {e}")
        return None

def nombre_jugador():
    """Con esta función le generamos un nombre al jugador."""
    i = 1
    while True:
        yield f"Jugador{i}"
        i += 1
def leer_clave():
     #Cargar la clave privada del usuario
    try:    
        fichero_path = Path(__file__).parent / "privada_servidor_sieteymedia.pem"
        with open(fichero_path, 'r') as file:
            private_key = RSA.import_key(file.read())
        key_size = private_key.size_in_bytes()

        fichero_path = Path(__file__).parent / "publica_usuarioA_sieteymedia.pem"
        with open(fichero_path, 'rb') as file:
            recipient_key = RSA.import_key(file.read())

        return recipient_key, key_size, private_key
    
    except Exception as e:
        print(f"Error al leer la clave privada: {e}")
        return None, 0
    

if __name__ == "__main__":
    HOST = '127.0.0.1'
    PORT = 5000

    try:
        socket_escuchar = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('Socket servidor creado')
    except socket.error:
        print('Fallo en la creación del socket del servidor.')
        sys.exit()
    
    try:
        socket_escuchar.bind((HOST, PORT))
    except socket.error as e:
        print('Error socket: %s' %e)
        sys.exit

    socket_escuchar.listen(5)
    x = nombre_jugador()
    while True:
        #jugador aceptado
        socket_jugador, addr_jugador = socket_escuchar.accept()

        recipient_key, key_size, private_key = leer_clave()
        #creamos un hilo para el jugador aceptado
        jugador_thread = Jugador(socket_jugador, addr_jugador, next(x), key_size, private_key, recipient_key)              
        jugador_thread.start()
        



