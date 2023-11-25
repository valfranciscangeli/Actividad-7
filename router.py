import sys
import socket
from utils import *

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

if debug:
    print(
        f"direccion: {direccion_router_actual}, archivo de rutas: {router_rutas}")


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
    
    if paquete_ip.mensaje == "START_BGP": #si el mensaje es un mensaje de inicio de BGP
        run_BGP(router)

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
                    print("paquete completado:\n", paquete_reensamblado.mensaje)
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
                    direccion_next_hop = (ruta_encontrada[0], ruta_encontrada[1])
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

                            router.sendto(fragmento.encode(), direccion_next_hop)
                        except socket.error as e:
                            print(f"Error al enviar datos: {e}")

                else:
                    print(
                        f"No hay rutas hacia {destination_address} para paquete {paquete_ip}\n")
        else:
            print(f"Se recibió paquete {paquete_ip} con TTL 0\n")
