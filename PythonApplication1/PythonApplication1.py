from xml.dom import minidom
import shlex, subprocess, csv, json, sys, time

#-------------------------EMPIEZA PRIMERA EJECUCIÓN DE NMAP. Para que escanae la red en busca de dispositivos y puertos abiertos-------------
command_line1 = 'nmap -sS --min-rate 5000 -p- --open -vvv -n -Pn '
command_line2 = '192.168.1.180' #EDITAR LA DIRECCIÓN IP Y MÁSCARA PARA ESCANEAR LA RED.
command_line3 = ' -oX allPorts.xml'
command = command_line1 + command_line2 + command_line3
	
args = shlex.split(command)
#Ejecuta el comando de búsqueda y guarda el resultado para el informe.
subprocess.call(args)

#----------------------------- FINALIZA EJECUCIÓN DE NMAP. Para que escanae la red en busca de dispositivos y puertos abiertos----------------

#---------------------------------------------------INICIO CARGA EL DICCIONARIO DE PUERTOS POR DEFECTO---------------------------------------
class servicioDefault():
	puerto = ""
	tipo = ""
	servicio = ""
class servicioDefaultDB():
	servicios = []

diccionarioServiciosDefecto = servicioDefaultDB()

def cargarServiciosDefault():
	path = "puertosPorDefecto.csv" #Path del fichero con el listado de servicios
	with open(path) as dbserviciosdefault:
		reader = csv.reader(dbserviciosdefault, delimiter=";")
		for row in reader: #Por cada fila se añade un servicio
			sd = servicioDefault()
			sd.puerto = row[0]
			sd.tipo = row[1]
			sd.servicio = row[2]
			diccionarioServiciosDefecto.servicios.append(sd) #Por cada fila se añade un servicio

#Llamamos a la función para cargar el diccionario
cargarServiciosDefault()
#---------------------------------------------------FINALIZA CARGA EL DICCIONARIO DE PUERTOS POR DEFECTO --------------------------------------

#-------------------------------------BUCLE PARA RECORGER EL REPORT Y BUSCAR COINCIDENCIAS EN EL DICCIONARIO Y searchsploit -------------------

#Buscamos coincidencias para puertos que pueden estar establecidos por defecto para algunas aplicaciones específicas.
def buscarYEncontrarExploits(puerto):
	for df in diccionarioServiciosDefecto.servicios:
		if df.puerto == puerto.id and df.puerto != "":
			puerto.name = df.servicio
			#Ahora hace la consulta a searchExploit
			command_line1 = 'searchsploit -t '
			command_line2 = puerto.name
			command = command_line1 + command_line2

			#Ejecuta el comando de búsqueda y guarda el resultado para el informe.
			return subprocess.getoutput(command)


#Buscamos coincidencias en searchploit para lo que ha detectado NMAP
def buscarCoincidenciasSearchploit(ficheroXML):
			#Ahora hace la consulta a searchExploit
			command_line1 = 'searchsploit -t --nmap'
			command_line2 = ficheroXML
			command = command_line1 + command_line2

			#Ejecuta el comando de búsqueda y guarda el resultado para el informe.
			return subprocess.getoutput(command)
		
	
#-----------------------------------------FIN DEL BUCLE PARA RECORGER EL REPORT Y BUSCAR EN EL DICCIONARIO Y searchsploit ---------------------

#-----------------------------------------A TRAVÉS DEL TTL COMPROBAMOS QUE SISTEMA OPERATIVO HAY DETRÁS----------------------------------------
def ttl_scan(ip):

	#64 bytes from 10.0.2.5: icmp_seq=1 ttl=64 time=0.312 ms
	command_line1 = 'ping -c 1 ' # Enviamos un único paquete para comprobar el ttl
	command = command_line1 + ip
	
	#args = shlex.split(command)
	result = subprocess.getoutput(command) # Ejemplo de cadena: "64 bytes from 10.0.2.5: icmp_seq=1 ttl=64 time=0.312 ms"
	char = '=' #Separador por '='
	resultado_ping = result.split() # Separamos el resultado por espacios.
	numero = resultado_ping[5].split(char) # Utilizamos el separador '=' para quedarnos solo con el número, valor del ttl
	
	ttn_int = 0
	try:
	    ttl_int = int(numero[1])
	except :
	    return "No se ha podido detectar el SO" 
	
	if ttl_int <= 64 and ttl_int != 0: # Comprobamos si el valor del TTL es menor de 64
		return "UNIX/Linux"
	else:
		return "Windows" # Si es mayor de 64 es un Windows.

	#El valor del TTL se puede ver alterado cuando hay algún elemento de red en medio, pero la alteración es en valor uno o dos.


#------------------------------------------------------------FIN COMPROBACIÓN DEL SO TTL -----------------------------------------------------

class ReportHost():
	ip = ""
	mac = ""
	SO = ""
	ports = []

class port():
	id = ""
	name = ""
	protocol = ""
	state = ""
	reason = ""
	reason_ttl = ""
	url = ""
	extraInfo = ""
	servicioPorDefecto = ""
	resultadoSearhExploit = ""
	

doc = minidom.parse('allPorts.xml') #Lee el primer escaneo

#Lineas de report
report = []

#3
#Función que ejecuta el segundo escaneo por equipo pasando como parámetro la ip y los puertos abiertos
#Devuelve el resultado en xml
def runSecondNMAP(ip, ports):
	command_line1 = 'nmap -sC -sV -p'
	command_line2 = ports + " " + ip
	command = command_line1 + command_line2
	
	args = shlex.split(command)
	subprocess.call(args)
	insertLine(ip)
	
#2
#Procesamos el XML obtenido para cada uno de los equipos y lo guardamos como una línea en el report.
#Esta parte de la ejecución lo que hace es recorer el fichero XML creado para cada uno de los Equipos detectados.
def insertLine(ipAddress):
	xml_puertos = minidom.parse(ipAddress + '_ports')
	line = ReportHost()
	host = xml_puertos.getElementsByTagName("host")
	for h in host:
		IPS = h.getElementsByTagName("address")
		for IP in IPS:
			if IP.getAttribute("addrtype") == "ipv4":
				line.ip = IP.getAttribute("addr")
				line.SO = ttl_scan(line.ip)
				line.puertos = h.getElementsByTagName("port")
				for p in line.puertos:
					p1 = port()
					p1.id = p.getAttribute("portid")
					p1.name= p.getAttribute("name") #Esto esta dentro de otra etiqueta
					p1.protocol = p.getAttribute("protocol")
					p1.state = p.getAttribute("state")
					p1.reason_ttl = p.getAttribute("reason_ttl")
					p1.resultadoSearhExploit = buscarCoincidenciasSearchploit(ipAddress + '_ports')
					p1.servicioPorDefecto = buscarYEncontrarExploits(p1)
					if p1.servicioPorDefecto == "": p1.servicioPorDefecto = "No se ha detectado una aplicación por defecto para este puerto"
					line.ports.append(p1)

			elif IP.getAttribute("addrtype") == "mac":
				line.mac = address.getAttribute("addr")
				

	report.append(line)
	
dispositivos= doc.getElementsByTagName("host")

contador = 0

#1
#Ejecuta por cada uno de los dispositivos de la lista un escaneo más profundo y guarda el resultado con formato XML en una lista.
for dispositivo in dispositivos:
	
	contador = contador + 1 #Número de equipo descubierto
	addresses = dispositivo.getElementsByTagName("address") #Direcciones del host
	print("Dispositivo encontrado: " + str(contador))
	#Recorre cada uno de los equipos encontrados, generando una nueva consulta a nmap para cada uno de ellos.
	for address in addresses:
		#Si la dirección es una dirección IPv4 se muestra como tal
		if address.getAttribute("addrtype") == "ipv4":
			print("Address:%s " % address.getAttribute("addr"))
			direccionIP = address.getAttribute("addr")

		#Si la dirección es una dirección MAC se muestra como tal
		elif address.getAttribute("addrtype") == "mac":
			print("Mac:%s " % address.getAttribute("addr"))

			#Aqui vamos mostrar todos los puertos que se han encontrado abiertos.
			puertos = dispositivo.getElementsByTagName("port")
			puertos_array = ['0'] #Puertos en string para que ejecutar la segunda parte del escaneo

			#Recorre cada uno de los puertos detectado para elaborar la segunda consulta a nmap
			for puerto in puertos:
				numeroPuerto = puerto.getAttribute("portid")
				puertos_array.append(numeroPuerto)

			#Llama a la función para ejecutar el anális más en profundidad. Lo muestra por pantalla.
			#y guarda un fichero XML con el resultado.
			runSecondNMAP(direccionIP, ",".join(puertos_array) + " -oX " + direccionIP + "_ports")


#4
#Una vez obtenida toda la información generamos un CSV formateado para informe.
def generarReportCSV():
	with open('reportEscaneoNMAP.csv', 'w', newline='') as csv_file:
		for host in report:
			writer = csv.writer(csv_file)
			writer.writerow(["IP", "MAC", "SO"])
			writer.writerow([host.ip, host.mac, host.SO])
			writer.writerow(["Ports"])
			writer.writerow(["ID", "Name", "Protocol", "State"])
			for port in host.ports:
				writer.writerow([port.id, port.name, port.protocol, port.state])
				writer.writerow(["Busqueda searchsploit: ", port.resultadoSearhExploit])
				writer.writerow(["Aplicación por defecto: ", port.servicioPorDefecto])

generarReportCSV()

#4
#Una vez obtenida toda la información generamos un JSON formateado para informe.
##Se puede llamar de forma adicional a esta función para guardar un fichero JSON.
def generarReportJSON():

	data = {}
	data['host'] = []
	data['puerto'] = []

	with open('reportEscaneoNMAP.json', 'w', newline='') as json_file:
		for host in report:
			data['host'].append({
			'IP': host.ip,
			'MAC': host.mac,
			'SO': host.SO
			})

			for port in host.ports:
				data['puerto'].append({
				'id': port.id,
				'nombre': port.name,
				'protocolo': port.protocol,
				'Busqueda searchsploit: ': port.resultadoSearhExploit,
				'Aplicación por defecto: ': port.servicioPorDefecto,
				})

		with open('data.txt', 'w') as outfile:
			json.dump(data, outfile)

generarReportJSON()
