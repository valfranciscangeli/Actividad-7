import sys
import socket
from utils import *
import copy
import time

# debug? ==================================================
debug: bool = False

# recibimos los parámetros desde consola =========================================
argumentos: list = sys.argv
router_IP = argumentos[1]
router_puerto = int(argumentos[2])
router_rutas = argumentos[3]

# variables globales ============================================================
direccion_router_actual = (router_IP, router_puerto)
buff_size = 4096

if cola_de_rutas.is_empty():
    cola_de_rutas = leer_archivo(router_rutas)

if debug:
    print(
        f"direccion: {direccion_router_actual}, archivo de rutas: {router_rutas}")

# funciones para BGP ==============================================================


def create_BGP_message(init: bool = True):
    ttl = 100
    id = random.randint(0, 99999999)
    mensaje = "START_BGP"
    if not init:
        mensaje = f"BGP_ROUTES\n{router_puerto}\n"
        if cola_de_rutas.is_empty():
            print("cola de rutas se encuentra vacia...\n")
        if debug:
            print("cola de rutas:", cola_de_rutas.queue)
        for ruta in cola_de_rutas.queue:
            ruta_ASN = ruta["ruta_ASN"]
            ruta_ASN = ' '.join(map(str, ruta_ASN)).strip()
            mensaje += f"{ruta_ASN}\n"

        mensaje += "END_BGP_ROUTES"

    paquete_IP = PaqueteIP(router_puerto, ttl, id, 0, len(
        mensaje.encode()), 0, mensaje)
    return create_packet(paquete_IP)


# test:
if debug:
    # mensaje de inicio
    print("mensaje BGP de inicio:", create_BGP_message())
    # mensaje con rutas, la cola de rutas esta vacia en este punto
    print("mensaje BGP de rutas:", create_BGP_message(init=False))


def run_BGP(socket):
    print("iniciando bpg ... \n")
    cola_inicial = copy.deepcopy(cola_de_rutas.queue)
    tiempo_espera = 100
    tiempo_inicio = time.time()
    inicio = True
    while True:
        if time.time() - tiempo_inicio > tiempo_espera:
            break
        print("\nnueva vuelta del ciclo principal...\n")
        vecinos = extraer_vecinos(cola_de_rutas.queue)
        for vecino in vecinos:
            vecino = vecino[0]
            direccion_envio = (router_IP, int(vecino[0]))
            # debemos enviar el mensaje de que inicien BGP
            if inicio:
                print("\n enviamos inicio BGP...\n")
                socket.sendto(create_BGP_message().encode(), direccion_envio)
                inicio = False
            # enviamos nuestra tabla de rutas
            print("\n enviamos tabla de rutas...\n")
            socket.sendto(create_BGP_message(
                False).encode(), direccion_envio)
            tiempo_inicio = time.time()

        sale_por_mensaje = False
        while time.time() - tiempo_inicio < tiempo_espera:
            print("\nesperamos recibir algun mensaje ...\n")
            # revisamos si nos mandaron algo
            recv_message, return_address = socket.recvfrom(buff_size)
            if recv_message != None:  # si recibimos algo no vacio
                paquete_ip = parse_packet(recv_message)
                if "BGP_ROUTES" in paquete_ip.mensaje:  # si no es un mensaje de inicio de BGP
                    print(
                        f"\nse recibio un mensaje ...\nmensaje: {str(paquete_ip)}\n")
                    sale_por_mensaje = True
                    break

        if sale_por_mensaje:
            print("\nentramos a procesar las rutas recibidas...\n")
            mensaje_dividido = paquete_ip.mensaje.split("\n")
            # las lineas que contienen a las rutas ASN van desde el indice 2 hasta el -1
            mensaje_dividido = mensaje_dividido[2:len(
                mensaje_dividido)-1]
            mensaje_dividido = [v.split(" ") for v in mensaje_dividido]

            for valor in mensaje_dividido:
                print(f"\nentramos a procesar la ruta {valor}...\n")
                diccionario = {
                    "red": "127.0.0.1",
                    "ruta_ASN": valor + [str(router_puerto)],
                    "ip_siguiente_salto": "127.0.0.1",
                    "puerto_siguiente_salto": int(valor[-1]),
                    "MTU": 1000
                }

                # significa que este router no se encuentra en la ruta
                if str(router_puerto) in valor:
                    print("\nruta descartada, somos parte ...\n")
                else:
                    lo_tengo = False
                    for elemento in cola_de_rutas.queue:
                        lo_tengo = valor[0] == elemento["ruta_ASN"][0]

                    if not lo_tengo:  # no tengo ruta hacia ese router, así que debemos guardarla
                        print("no teniamos el elemento, asi que lo guardamos...\n")
                        cola_de_rutas.enqueue(diccionario)

                    else:  # debo revisar si esta ruta nueva es mas corta
                        print("ya teniamos el elemento...\n")

                        print(
                            "revisamos si esta ruta es mas corta que la que tenemos...\n")
                        for elemento in cola_de_rutas.queue:
                            ruta_actual = elemento["ruta_ASN"]
                            if str(valor[0]) == str(ruta_actual[0]):
                                if len(ruta_actual) > len(diccionario["ruta_ASN"]):
                                    cola_de_rutas.queue.remove(
                                        elemento)
                                    cola_de_rutas.enqueue(
                                        diccionario)
                                else:
                                    print(
                                        "la nueva ruta no era mas corta que la actual...")

        if comparar_listas_diccionarios(cola_inicial, cola_de_rutas.queue):
            print("la tabla de rutas no ha cambiado...\n")
            break
        else:
            print("la tabla de rutas es distinta...\n")
            cola_inicial = copy.deepcopy(cola_de_rutas.queue)
    return str(cola_de_rutas)


# creacion del socket ============================================================
# socket no orientado a conexión
router = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# unimos el socket a la dirección de este router
router.bind(direccion_router_actual)

# esperamos hasta recibir un mensaje ==============================================

# acá guardamos un diccionario de los paquetes que nos llegan para nosotros
mis_paquetes = dict()

# vamos a recibir mensajes en un loop
while True:

    # aquí esperaremos hasta recibir algun mensaje
    while True:
        print("================================\nesperando mensaje ...\n")

        # recibimos el mensaje usando recvfrom
        recv_message, return_address = router.recvfrom(buff_size)

        if debug:
            print(f"mensaje recibido: |{recv_message.decode()}|\n")

        # si recibimos un mensaje saldremos de este ciclo para continuar con el código
        if recv_message != None:
            print("Se recibió un fragmento ... \n")
            break

    paquete_ip = parse_packet(recv_message)  # retorna un paquete IP
    destination_address = (paquete_ip.ip, paquete_ip.puerto)
    ttl = paquete_ip.ttl

    if paquete_ip.mensaje == "START_BGP":  # si el mensaje es un mensaje de inicio de BGP
        print("Tabla de rutas actualizada:",run_BGP(router))

    else:
        if ttl > 0:  # agregamos condicion de que tenga vida para procesarlo

            # si el mensaje es para nosotros ...
            if destination_address == direccion_router_actual:
                # lo guardamos en el diccionario
                # rescatamos el id del paquete
                current_id = paquete_ip.id
                # guardamos el paquete en el diccionario
                if current_id in mis_paquetes:
                    mis_paquetes[current_id].append(create_packet(paquete_ip))
                else:
                    mis_paquetes[current_id] = [create_packet(paquete_ip)]
                mis_paquetes[current_id] = list(
                    set(mis_paquetes[current_id]))  # eliminamos duplicados

                paquete_reensamblado = reassemble_IP_packet(
                    mis_paquetes[current_id])
                if paquete_reensamblado != None:
                    paquete_reensamblado = parse_packet(
                        paquete_reensamblado.encode())
                    print("paquete completado:\n",
                          paquete_reensamblado.mensaje)
                    # como ya llego completo liberamos este id del diccionario
                    del mis_paquetes[current_id]
                else:
                    if debug:
                        print(f"fragmentos que hay: {mis_paquetes}\n")
            # debemos reenviar el paquete
            else:
                # buscamos una direccion para reenviar
                ruta_encontrada = check_routes(
                    router_rutas, destination_address)
                # revisamos si encontramos ruta de reenvio
                if ruta_encontrada != None:
                    direccion_next_hop = (
                        ruta_encontrada[0], ruta_encontrada[1])
                    mtu = int(ruta_encontrada[2])
                    # vamos a disminuir el ttl antes de mandar
                    paquete_ip.ttl = ttl-1

                    # creamos el paquete completo:
                    paquete_completo = create_packet(paquete_ip).encode()

                    fragmentos = fragment_IP_packet(paquete_completo, mtu)
                    if debug:
                        print("resultado de la fragmentación del paquete:",
                              fragmentos, "\n")

                    for fragmento in fragmentos:
                        # hacemos forward
                        try:
                            # avisamos que se va a mandar
                            print(
                                f"redirigiendo paquete {fragmento} con destino final {destination_address} desde {direccion_router_actual} hacia {direccion_next_hop}.\n")

                            router.sendto(fragmento.encode(),
                                          direccion_next_hop)
                        except socket.error as e:
                            print(f"Error al enviar datos: {e}")

                else:
                    print(
                        f"No hay rutas hacia {destination_address} para paquete {paquete_ip}\n")
        else:
            print(f"Se recibió paquete {paquete_ip} con TTL 0\n")
