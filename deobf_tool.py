"""
Todo el proceso de como llegue a esto, esta explicado en el articulo de medium
en el hipervinculo que deje en el readme.

Para resumirlo por si te da flojera leer mi articulo, el malware consiste en 3 etapas:
La primera etapa consiste de un archivo .zip encriptadon con AESGCM, La segunda consiste
en un archivo .xz que luego es deszipeado para asi ejecutar la ultima etapa, la ultima etapa
consiste en un archivo .pyc que es ejecutado usando builtins.exec().

Ahora, esta herramienta esta enfocada en obtener el token del bot o el webhook de discord
a donde envia los datos el atacante, la razon de no conseguir el codigo fuente de una
es porque lo intente y no pude conseguir el codigo fuente del archivo final, y tambien
porque no es necesario porque el codigo del stealer es publico, por ende tanto ustedes
como yo, podemos verlo y saber que hace el malware realmente, lo que unicamente cambia
es el token, y por eso unicamente enfoque el script para conseguir el token. 
"""

import re
import base64
import zlib
import zipfile
import os
import glob
import lzma
import codecs
import sys
from colorama import Fore,init
from Crypto.Cipher import AES
from pyinstxtractor import generate_pyc_files

def decrypt_content(key, iv , content):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv) #desencriptado GCM
    return cipher.decrypt(content) 
##########################################
def fase3_malware_source_code(path:str):
    final_list = []
    try:
        with open(path , "r") as l:
            conty = l.read()
            #Esta regex simplemente obtiene las variables del archivo final
            #para luego ser de codificado y desofuscado para obtener el bytecode final
            x = r'_{4,7}=\"([A-Za-z_0-9\/+=])+\";'
            for match in re.finditer(x , conty):
                x = re.sub(r'_{4 , 7}=','',str(match.group())) #Esto elimina esto '___='
                tabla = str.maketrans("" , "" , '_";') #Esto elimina el resto de caracteres que no nos importa
                resultado = str(x.translate(tabla))
                final_list.append(resultado[1::])
        #Si leyeron el articulo sabran el porque de esta linea        
        payload_base64 = codecs.decode(final_list[1], "rot13") + final_list[2] + final_list[3][::-1] + final_list[0]
        bytecode = base64.b64decode(payload_base64)
        output_file = sys.argv[2] 
        with open(output_file, "wb") as f:
            f.write(bytecode)
        with open(output_file , "rb") as t:
            content_binary_file = str(t.read())
            token_webhook = re.search(r'[Ss]ettingszP([\w]+)==?' , content_binary_file) #Con este regex conseguimos el token
            print(Fore.GREEN + f"[+] Token o Webhook encontrado: {base64.b64decode(token_webhook.group().replace("SettingszP" , ''))}" + Fore.RESET)
        print(Fore.GREEN + "[+] Fase 3 completada" + Fore.RESET)
        print(Fore.GREEN + f"[+] Bytecode guardado en {output_file}" + Fore.RESET)
    except Exception as err:
        print(Fore.RED + f"[+] Ha ocurrido un error en la fase 3: {str(err)}" + Fore.RESET)

def fase2_extract_and_unxz(path:str):
    try:
        file = glob.glob(f"{path}/*.pyc") #obtenemos todos los pyc que esten en la ruta que le pasemos a la funcion
        with open(file[0] , "rb") as fase2:
            contenido = fase2.read()
            # El header y el footer, son simplemente los bytes del inicio y del final
            # del archivo .xz, con esto simplemente buscamos el inicio y el final, para
            # asi obtener el archivo .xz del archivo .pyc
            header = bytes.fromhex("FD 37 7A 58 5A 00")
            footer = bytes.fromhex("00 00 00 00 04 59 5A")
            inicio = contenido.find(header)
            if inicio == -1:
                print(Fore.RED + "[+] No se encontró el encabezado del archivo XZ." + Fore.RESET)
                return
            fin = contenido.find(footer, inicio)
            if fin == -1:
                print(Fore.RED + "[+] Se encontró el inicio pero no la firma de fin." + Fore.RESET)
                return
            fin += len(footer)
            archivo_extraido = contenido[inicio:fin] #aca guardamos el archivo .xz
            #Guardamos y leemos el contenido del archivo .xz
            with open("archivo.xz", "wb") as f_out:
                f_out.write(archivo_extraido)
            with lzma.open("archivo.xz" , "rb") as xz_file: 
                p = xz_file.read()
            #Guardamos el contenido en un archivo final de python
            with open("final_script.py" , "wb") as final_sc:
                final_sc.write(p)
        os.remove(file[0])
        os.remove("archivo.xz")
        print(Fore.GREEN + "[+] Fase 2 completada" + Fore.RESET)
        fase3_malware_source_code("final_script.py")
    except Exception as err:
        print(Fore.RED + f"[+] Ha ocurrido un error con la fase 2: {str(err)}" + Fore.RESET)

def fase1_extract_and_unzip(generate_folder:str):
    # La variable de abajo lo que haran sera buscar todos los archivos pyc
    # para luego filtrar por el que nos interesa.
    folder_pyc = glob.glob(f"{generate_folder}/*.pyc")
    pyc_file = ""

    for i in folder_pyc:
        # Esto lo que hace es buscar el archivo main que es el que contiene
        # el archivo .zip encriptado.
        # El porque de ese nombre todo raro lo explico en mi articulo :D
        r = re.match(r'(\w{8})-(\w{4})-(\w{4})-(\w{4})-(\w{12})\.pyc' , str(i.replace(generate_folder + "\\" , "")))
        if r:
            pyc_file = i
    try:
        if pyc_file == "":
            raise ValueError("No se encontro el pyc con las llaves de desencriptacion")
            os._exit(1)
        with open(pyc_file, "rb") as l:
            content = str(l.read())
            # Lo que sigue son regex que buscan la respectiva llave y el iv necesario
            # para usar aesgcm, y con eso desencriptar y convertir devuelta a un
            # .zip y luego descomprimirlo para obtener el archivo .pyc y ejecutar
            # la segunda fase de este script.

            key_r = re.search(r'[A-Za-z0-9\/=+]{44}' , content).group()
            iv_r = re.search(r'=([\w\\]){8}([A-Za-z0-9\/=+]){16}' , content).group()
            iv_r1 = re.sub(r'^=[\w\\]{8}' ,'' ,str(iv_r))
            key = base64.b64decode(key_r)
            iv = base64.b64decode(iv_r1)

            print(Fore.GREEN + f"[+] Llave: {key}\n[+] IV: {iv}" + Fore.RESET)
        # Leemos el archivo 'blank.aes' que contiene el archivo .zip encriptado
        with open('blank.aes' , "rb") as blank:
            ciphertext = blank.read()
        # Volteamos el contenido del archivo previamente leido y luego lo descomprimimos
        ciphertext = zlib.decompress(ciphertext[::(-1)])
        with open("final.zip" , "wb") as fnpyc:
            # Escribimos el contenido encriptado al final
            fnpyc.write(decrypt_content(key , iv , ciphertext)) 

        # Una vez guardado, simplemente descomprimimos su contenido en la carpeta 'ofuscacion'
        with zipfile.ZipFile("final.zip", 'r') as zip_ref:
            zip_ref.extractall("./ofuscacion")
        os.remove("final.zip")
        print(Fore.GREEN + "[+] Fase 1 completada" +Fore.RESET)
        fase2_extract_and_unxz("./ofuscacion")
    except Exception as err:
        print(Fore.RED + f"[+] Error en la fase 1: {str(err)}" + Fore.RESET)
init()
if len(sys.argv) < 3:
    print(Fore.RED + f"Porfavor ingresa los argumentos necesarios\n\"{sys.argv[0]} malware.exe final_payload.bin\"" + Fore.RESET)
    os._exit(1)
generate_pyc_files(sys.argv[1])
print("")
generate_folder = sys.argv[1] + "_extracted"
fase1_extract_and_unzip(generate_folder)