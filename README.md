![Nadi grosera](https://github.com/papitapro1234/F-CK-BLANK-GRABBER/blob/main/Nadi-Grosera.jpg)

# Esto es un script sencillo, pensado para obtener el token o el webhook del stealer conocido como `BLANK-GRABER`.

### `Consiste en 3 fases:`

- ### `1)` La primera fase consiste en la identificación del archivo ‘.pyc’ principal, y luego la obtención de la ‘llave’ y del ‘iv’ necesarios para desencriptar el archivo ‘`.aes`’, luego de la obtención de ambos datos, se procede a la descompresión de los bytes previamente puestos en orden, para luego ser desencriptados usando `AES256GCM`, y el contenido ser puesto en un archivo llamado ‘final.zip’, para luego ser descomprimido en una carpeta llamada ‘ofuscacion’, esta carpeta contiene un archivo ‘.pyc’, que contiene la segunda fase del stealer.

- ### `2)` La segunda fase consiste en la lectura del archivo que nos dejó la fase anterior, para luego identificar dentro de sus bytes en formato hexadecimal, los [`magic bytes`](https://en.wikipedia.org/wiki/List_of_file_signatures) de un archivo ‘.xz’, una vez se encuentra el patrón hexadecimal, se procede a la extracción del archivo ‘`.xz`’ que se encuentra en el archivo ‘.pyc’, una vez se obtiene se guarda el archivo y se procede devuelta la descompresión y obtención de un archivo ‘.py’, este archivo final contiene los bytes del stealer que son ejecutados en la tercera fase.

- ### `3)` La tercera fase consiste en la identificación de las variables ofuscadas del archivo ‘.py’, que obtuvimos de la fase anterior, una vez habiendo identificado las variables, procedemos a eliminar algunos caracteres que no nos interesan, para únicamente quedarnos con el valor almacenado en esas variables, una vez obtenemos esos valores, procedemos a ejecutar un algoritmo de descifrado, que previamente descubrí usando métodos de ingeniería inversa, mostrado y explicados en mi artículo de médium, una vez desofuscamos los valores, procedemos a guardar el resultado en un archivo ‘.pyc final’, para luego leer ese archivo y usando regex ([`Regular Expresion`](https://es.wikipedia.org/wiki/Expresi%C3%B3n_regular)) , obtener el valor en base64 que corresponde al token o webhook del bot a donde se envía la información.

---
## El cómo funciona el script, está mucho mejor detallado y explicado en mi artículo de médium, que estoy dejando en el siguiente [hipervínculo](https://medium.com/@jesus_papita_55717/como-un-stealer-hecho-en-python-me-dio-dolor-de-cabeza-blank-grabber-4fd4f7eded9b).

![Yamada spin](https://media1.tenor.com/m/77fMTJtb_8sAAAAC/dangers-in-my-heart-spin.gif)
