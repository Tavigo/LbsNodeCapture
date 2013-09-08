package com.kiribuki.nodecapture;


import java.util.concurrent.LinkedBlockingQueue;


import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonClientException;

import com.amazonaws.auth.ClasspathPropertiesFileCredentialsProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSAsyncClient;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.SendMessageBatchRequest;
import com.amazonaws.services.sqs.model.SendMessageBatchRequestEntry;

import com.google.gson.Gson;

import com.kiribuki.nodecapture.IEEE802dot11_RADIOTAP;
import com.kiribuki.nodecapture.IEEE802dot11_RADIOTAP.DataField_DBM_ANTENNA_SIGNAL;
import com.kiribuki.nodecapture.SendPacketCapture;
import com.kiribuki.packetcapture.PacketCapture;

import java.util.ArrayList;  
import java.util.List;  

import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapIf;  
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;


import org.jnetpcap.util.resolver.IEEEOuiPrefixResolver;

import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;

public class NodeCapture {
	
	static LinkedBlockingQueue<PacketCapture> queue; // Cola de frames capturados
	static String QueueName;                         // Nombe de la cola del servcio SQS de Amazon  
	static byte[] nodeMAC;                           // MAC del dispositivo que captura los frames
	static float longitud=0;                         //
	static float latitud=0;                          //        
	static int lenMAC=6;

	static int fromPunter = 0;
	static int toPunter = 0;
	static int BSSIDPunter = 0;
	
	static int framestotales = 0;
	static int framesdescartados = 0;
	static int framesencolados = 0;
	static int framesNoFromMAC = 0;
	static int framesNoRSSI = 0;
	static int framesAleatorios = 0;
	
	static long messagesSend = 0;      // Numero de mensajes enviados
	
	static int frames;

	static IEEEOuiPrefixResolver xiu = new IEEEOuiPrefixResolver();
	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		
		
		
		//xiu.initializeIfNeeded();
		
		
	    int numDis=-1;
	    String dispositivo;
	  
	    for(int i=0; i < args.length; i++) {
	        System.out.println( args[i] );	
	    }
	    
		if (args.length >= 1) {
			dispositivo = args[0];
			QueueName = args[1];
			longitud = Float.parseFloat(args[2]);
			latitud = Float.parseFloat(args[3]);
			System.out.println("Dispositivo de captura: " + dispositivo);
		} else {
			System.out.println("Falta parámetro de entrada");
			return;
		}
		
		/******************************************************************/
		/* Creación de la cola i el nuevo Thread que enviarà los mensajes */
		/******************************************************************/
		queue = new LinkedBlockingQueue<PacketCapture>();
		new Thread(new NodeCapture().new Consumer()).start();
		new Thread(new NodeCapture().new Logs()).start();
		
		/*
		 *  Registro del Radiotap Header 
		*/
		//JRegistry.registerResolver(org.jnetpcap.util.resolver.Resolver.ResolverType.IEEE_OUI_PREFIX, xiu);
		JRegistry.registerResolver(IEEEOuiPrefixResolver.class, xiu);
		xiu.initializeIfNeeded();
		
		try {
			int headerID = JRegistry.register(IEEE802dot11_RADIOTAP.class);
			
			System.out.printf("Header registrado con éxtio, su ID es %d\n", headerID); 
		} catch (RegistryHeaderErrors e) {  
			  e.printStackTrace();  
			  System.exit(1);  
		}
		
		/*
		 *  Presentamos por pantalla los Headers que estan registrados, y que 
		 *  podemos utilizar en la captura de los frames
		 */
		System.out.println(JRegistry.toDebugString());
		
		
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Willry { be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
  
        /* 
         * Lista de todos los dispositivos men el sistema
         */ 
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK ) {  
            System.err.printf("No se pueden leer los dispositivos del sistema %s", errbuf  
                .toString());  
            return;  
        }  
  
        if ( alldevs.isEmpty()) {  
            System.err.printf("No hay dispositivos disponibles en el sistema; alldevs.isEmpty");  
            return;  
        }  
        
        System.out.println("Dispositivos encontrados:");  
  
        /* 
         * De la lista de dispositivos disponibles, elegimos el que nos interesa
         */
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "Descripción no disponible";
            if (dispositivo.equals(device.getName().toString())) {
            	System.out.println("Encontrado");
            	
            	numDis = i;
            	nodeMAC = device.getHardwareAddress();
            	System.out.printf(xiu.resolveToName(nodeMAC, xiu.toHashCode(nodeMAC)));
            	
           
            }
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
            
        }  
        
        if (numDis == -1 ) {
        	System.out.println("Dispositivo no encontrado.");
        	System.exit(0) ;
        }
        
        PcapIf device = alldevs.get(numDis);   
        System.out  
            .printf("\nDevice escogido para la captura '%s'\n",  
                (device.getDescription() != null) ? device.getDescription()  
                    : device.getName());  
  
        /*
         * Abrimos el dispositivo seleccionado
         */ 
        int snaplen = 64 * 1024;           // Captura de todo el paquete 
        int flags = Pcap.MODE_PROMISCUOUS; // Modo de captura promiscuo (todo el tráfico)
        int timeout = 10 * 1000;           // 10 segundos en  millis  
        Pcap pcap =  
            Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
        if (pcap == null) {  
            System.err.printf("Error abriendo el dspositivo para capturar paquetes: "  
                + errbuf.toString());  
            return;  
        }  
  
        /*
         * Creación de un Manejador de paquetes.
         */  
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
        	public void nextPacket(PcapPacket packet, String user) {
        		// Definimos el header Radiotap, y el valor del RSSI
            	IEEE802dot11_RADIOTAP radiotap = new IEEE802dot11_RADIOTAP();
            	DataField_DBM_ANTENNA_SIGNAL RSSI = new DataField_DBM_ANTENNA_SIGNAL();
            	
            	int punter;
            	int maxframes = 0;
            	Boolean swQueue = false;
            	
            	// Si detectamos el header radiotap, extaremos los datos y enviamos el paquete a la cola
            	if (packet.hasHeader(radiotap)) {
            		punter = radiotap.len();
            		PacketCapture packetcapture = new PacketCapture();
            		// Carga de los datos del paquete en el objeto packetcapture
            		packetcapture.SetFechaCaptura(packet.getCaptureHeader().timestampInMillis());
               	 	packetcapture.Setwirelen(packet.getCaptureHeader().wirelen());
            		packetcapture.SetNodeMAC(FormatUtils.mac(nodeMAC));
            		packetcapture.SetLongitud(longitud);
            		packetcapture.SetLatitud(latitud);
            		// Obtenemos el valor del RSSI del RAdiotap Header
            		if ((radiotap.present_AntennaSignal()==1) && (radiotap.hasSubHeader(RSSI)==true)) {
            			packetcapture.SetRSSI(RSSI.DBM_ANTENNA_SIGNAL());
            			if (packetcapture.GetRSSI() > 0 ) {
            				System.out.print(radiotap);
            				//System.exit(0);
            			}
            		}
            		packetcapture.SetTipoFrame(packet.getByte(punter));
            		byte[] FrameControl = packet.getByteArray(punter, 2);
            		// Obtenemos las direcciones MAC presentes en el farem capturado
            		fromPunter = 0;
            		toPunter = 0;
            		BSSIDPunter = 0;
            		if (PunterosDirecciones(punter, FrameControl )) {
            			if (fromPunter > 0) {
            				packetcapture.SetfromMAC(FormatUtils.mac(packet.getByteArray(fromPunter,lenMAC)));
            			}
    					if (toPunter > 0) {
    						packetcapture.SetToMAC(FormatUtils.mac(packet.getByteArray(toPunter,lenMAC)));
    					}
    					if (BSSIDPunter > 0) {
    						packetcapture.SetBSSID(FormatUtils.mac(packet.getByteArray(BSSIDPunter,lenMAC)));
            			}
            		}
            		packetcapture.SetSignalHash(packet.getByteArray(punter, packet.getCaptureHeader().wirelen()-punter));
            		
            		/* 
            		 * Si no tenemos la dirección MAC de origen, despreciaremos el frame, ya que
            		 * en este tipo de frames no tenemos información relevante para nuestro estudio
            		*/
            		swQueue= true;
            		if (swQueue) {
            			if (packetcapture.GetfromMAC() == null)  
            			{ 
            				swQueue = false;
            				framesNoFromMAC++;
            			}
            		}
            		/*
            		 * Si la MAC del emisor es la misma que la MAC del NodeCapture, también es un frame
            		 * si información relevante para nuestro estudio 
            		 */
            		if (swQueue) {
            		   if (packetcapture.GetfromMAC().equals(packetcapture.GetNodeMAC()))
            		   {
            			   swQueue = false;
            			   framesNoRSSI++;
            		   }
            		} 
            		/* 
            		 * Discriminación alaeatoria para no incorporar mensajes a la cola, i no provocar el colapso 
            		 * de esta en entornos con tránsito muy congestionado. 
            		 */
            		if (swQueue) {
            			frames++;
            			if (frames > 10) { frames = 1; }
            			
            			if (isBetween(queue.size(), 0, 100)) {
            				maxframes = 10;
            			} else if (isBetween(queue.size(), 101, 200)) {
            				maxframes = 9;
            			} else if (isBetween(queue.size(), 201, 300)) {
            				maxframes = 8;
            			} else if (isBetween(queue.size(), 301, 400)) {
              				 maxframes = 7;
            			} else if (isBetween(queue.size(), 401, 500)) {
             				 maxframes = 6;	 
            			} else if (isBetween(queue.size(), 501, 600)) {
             				 maxframes = 5;
            			} else if (isBetween(queue.size(), 601, 700)) {
             				 maxframes = 4;
            			} else if (isBetween(queue.size(), 701, 800)) {
             				 maxframes = 3;
            			} else if (isBetween(queue.size(), 801, 900)) {
             				 maxframes = 2;
            			} else if (isBetween(queue.size(), 901, 1000)) {
             				 maxframes = 1;	 
                		} else {
                			maxframes =0;
                		}
         				if (maxframes < frames) {
         					swQueue = false;
         					framesAleatorios++;
        				}
         				//System.out.printf("frames: %d maxframes: %d\n", frames, maxframes);
            		}
            		/*
            		 * Ponemos en la cola el Frame, si este es de interes para nuestro estudio
            		 */
               	 	if (swQueue) {
               	 		try {
               	 			queue.put(packetcapture);
               	 			framesencolados++;
               	 		} catch (InterruptedException e) {
               	 			e.printStackTrace();
               	 		}
               	 	} else {
               	 		framesdescartados++;
               	 	}
            	}
            	framestotales++;
            }  
        };
       
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "user");
        pcap.close();
	}
	
	static public boolean PunterosDirecciones(int punter, byte[] FrameControl) {
		boolean sw = true;
		int offset = punter + 4;
		toPunter = 0;
		fromPunter = 0;
		BSSIDPunter = 0;
		
		StringBuffer sb = new StringBuffer();
        for (int i = 0; i < FrameControl.length; i++) {
	         sb.append(Integer.toString((FrameControl[i] & 0xff) + 0x100, 16).substring(1));
	    }
		
		// Detectamos el tipo de frame, para extraer las direcciones MAC de origen y destino
  		int tipo = ((byte)0b00000011 & (byte)FrameControl[0] >> 2);
		
		switch (Integer.toBinaryString(tipo)) {
			// Frame de administración
			case "0":
				fromPunter = offset + 1 * lenMAC;
				toPunter =  offset;
				BSSIDPunter = offset + 2 * lenMAC;
				break;
			// Frame de Control
			case "1":			
				int subTipo = ((byte)0b00001111 & (byte)FrameControl[0] >> 4);
				switch (Integer.toBinaryString(subTipo)) {
					// Block Acknowledgment Request (QoS)
					// Block Acknowledgment (QoS)
					// RTS
					// Contention-Free (CF-End)
					// CF-End + CF-Ack
					case "1000": 	
					case "1001":
					case "1011":
					case "1110":
					case "1111":
						fromPunter =offset + 1 * lenMAC; 
						toPunter = offset;
						BSSIDPunter = 0;
						break;
					// Power Save (PS)-Poll
					case "1010":
						fromPunter = offset + 1 * lenMAC;
						toPunter = 0;
						BSSIDPunter = offset;
						break;
					//CTS
					// Acknowledgment (ACK)
					case "1100": 
					case "1101": 
						fromPunter = 0;
						toPunter = offset;
						BSSIDPunter = 0;
						break;
					default:
						sw = false;
						System.out.println("AGG");
						System.exit(1);
						break;
				}
				break;
			// Frame de Datos
			case "10":
				// En los frame de datos, dependiento de los subcampos ToDS y FromDS, los campos de
				// dirección pueden tener un valor u otro
				int DS =  ((byte)0b00000011 & (byte)FrameControl[1]);
				//System.out.printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! DS: %s\n", Integer.toBinaryString(DS));
				switch (Integer.toBinaryString(DS)) {
					//IBSS (ad-hoc)
					case "0":
						fromPunter = offset;
						toPunter = offset  + 1 * lenMAC;
						BSSIDPunter = offset + 2 * lenMAC;
						break;
					// Hacia AP (Infraestructura)
					case "1":
						fromPunter = offset + 1 * lenMAC;
						toPunter = offset + 2 * lenMAC;
						BSSIDPunter = offset;
						break;
					// Desde AP (Infraestructura)
					case "10":
						fromPunter = offset + 2 * lenMAC;
						toPunter = offset;
						BSSIDPunter = offset + 1 * lenMAC;
						break;
					//WDS bridge
					case "11":
						fromPunter = offset + 3 * lenMAC;
						toPunter = offset + 2 * lenMAC;
						BSSIDPunter = 0;
						break;
					default:
						sw = false;
						break;
				}
				break;
			default:
				sw = false;
				break;
		}
		
		
		if ( !sw ) {
			fromPunter = 0;
			toPunter = 0;
			BSSIDPunter = 0;
			System.out.println("No funciona!");
		}
		return sw;
	}
	
	
	static void Print(String message) {
		System.out.println(message);
	}
	
	/* 
	 * Thread encargado de enviar los mensajes de la cola al servivio de SQS de Amazon
	 */
	class Consumer implements Runnable {
		
		final int BATCH_SIZE = 10;  // Numero máximo de mensajes que podemos enviar en un Batch SQS (limitación Servivio Amazon)
		final int MAX_FAILSEND = 3; // Número máximo de intentos para enviar mensajes

		int failSend = 0;           // Numero de fallos al enviar mensajes
		
		AmazonSQS sqs = new AmazonSQSAsyncClient(new ClasspathPropertiesFileCredentialsProvider());
		Region euWest1 = Region.getRegion(Regions.EU_WEST_1);
		String myQueueUrl= "";
		String missatge;
		SendMessageBatchRequest smbr;
		Gson gson = new Gson();
		
		/*
		 *  Constructor de la clase Consumer
		 */
		Consumer() {
			sqs.setRegion(euWest1);
			CreateQueueRequest createQueueRequest = new CreateQueueRequest(NodeCapture.QueueName);
			myQueueUrl = sqs.createQueue(createQueueRequest).getQueueUrl();
			smbr = new SendMessageBatchRequest(myQueueUrl);
			smbr.setEntries(new ArrayList<SendMessageBatchRequestEntry>());
			NodeCapture.Print("Final Enlace con la cola de mensajess");
		}
	     @Override
	     public void run() { 
	    	while (true) {
	    		if (queue.isEmpty()) {
	    			try {
	    				Thread.sleep(100);
	    			} catch (InterruptedException e) {
	    				e.printStackTrace();
	    			}
	    		} else {
	    			while (!queue.isEmpty()) {
	    				messagesSend++;
	    				try {
	    					missatge = gson.toJson(queue.take()) ;
		    			} catch (InterruptedException e) {
		    				e.printStackTrace();
		    			}
	    				SendMessageBatchRequestEntry smbre = new SendMessageBatchRequestEntry();
	    				smbre.setMessageBody(missatge);
	    				smbre.setId("task_" + messagesSend);
	    				smbr.getEntries().add(smbre);
	    				if (smbr.getEntries().size() >= BATCH_SIZE) {
	    					// Enviamos los mensajes que hemos preparado
	    					Boolean swSend = true; 
	    					while (swSend) {
	    						try {
	    							sqs.sendMessageBatch(smbr);
	    							smbr.setEntries(new ArrayList<SendMessageBatchRequestEntry>());
	    							failSend = 0;
	    							swSend = false;
	    						} catch (AmazonServiceException ase) {
	    							NodeCapture.Print(ase.toString());
	    							//ase.printStackTrace();
	    							failSend++;
	    							if (failSend >= MAX_FAILSEND) {
	    								NodeCapture.Print("Excesivos errores al enviar los mensajes.");
	    								System.exit(1);
	    							}
	    							swSend=true;
	    						} catch (AmazonClientException ace) {
	    							NodeCapture.Print(ace.toString());
	    							//ase.printStackTrace();
	    							failSend++;
	    							if (failSend >= MAX_FAILSEND) {
	    								NodeCapture.Print("Excesivos errores al enviar los mensajes.");
	    								System.exit(1);
	    							}
	    							swSend=true;
	    						}
	    					}
	    				}
	    				
	    			}
	    		}
	    	}
	     }
	 }
	/*
	 * Classe que nos proporciona unos logs
	 */
	class Logs implements Runnable {
		
		int framestotales = 0;
		int framesdescartados = 0;
		int framesencolados = 0;
		int framesNoFromMAC = 0;
		int framesNoRSSI = 0;
		int framesAleatorios = 0;
		long messagesSend = 0;
		
		/*
		 * Constructor de la clase
		 */
		Logs() {
			NodeCapture.Print("Inicio de los Logs");
		}
		
		@Override
		public void run() { 
			while (true) {
				try {
    				Thread.sleep(60000);
    			} catch (InterruptedException e) {
    				e.printStackTrace();
    			}
				
				NodeCapture.Print("====   FRAMES TOTALES ======================================");
				NodeCapture.Print("Capturados              :" + Integer.toString(NodeCapture.framestotales));
				NodeCapture.Print("Descartados             :" + Integer.toString(NodeCapture.framesdescartados) + " " + Integer.toString(NodeCapture.framesdescartados * 100/NodeCapture.framestotales )+"%");
				NodeCapture.Print("   Descartados no from  :" + Integer.toString(NodeCapture.framesNoFromMAC) + " " + Integer.toString(NodeCapture.framesNoFromMAC * 100/NodeCapture.framestotales )+"%");
				NodeCapture.Print("   Descartados from=Node:" + Integer.toString(NodeCapture.framesNoRSSI) + " " + Integer.toString(NodeCapture.framesNoRSSI * 100/NodeCapture.framestotales )+"%");
				NodeCapture.Print("   Descartados Aleatoria:" + Integer.toString(NodeCapture.framesAleatorios)+ " " + Integer.toString(NodeCapture.framesAleatorios * 100/NodeCapture.framestotales )+"%");
				NodeCapture.Print("En Cola                 :" + Integer.toString(queue.size()) + " " + Integer.toString(queue.size() * 100/NodeCapture.framestotales )+"%");
				NodeCapture.Print("Enviados                :" + Long.toString(NodeCapture.messagesSend) + " " + Long.toString(NodeCapture.messagesSend * 100/NodeCapture.framestotales )+"%");
				NodeCapture.Print("  ---   FRAMES PARCIALES  ---  ");
				NodeCapture.Print("Capturados              :" + Integer.toString(NodeCapture.framestotales-framestotales));
				NodeCapture.Print("Descartados             :" + Integer.toString(NodeCapture.framesdescartados-framesdescartados) + " " + Integer.toString((NodeCapture.framesdescartados-framesdescartados) * 100/(NodeCapture.framestotales-framestotales) )+"%");
				NodeCapture.Print("   Descartados no from  :" + Integer.toString(NodeCapture.framesNoFromMAC-framesNoFromMAC) + " " + Integer.toString((NodeCapture.framesNoFromMAC-framesNoFromMAC) * 100/(NodeCapture.framestotales-framestotales) )+"%");
				NodeCapture.Print("   Descartados from=Node:" + Integer.toString(NodeCapture.framesNoRSSI-framesNoRSSI) + " " + Integer.toString((NodeCapture.framesNoRSSI-framesNoRSSI) * 100/(NodeCapture.framestotales-framestotales) )+"%");
				NodeCapture.Print("   Descartados Aleatoria:" + Integer.toString(NodeCapture.framesAleatorios-framesAleatorios)+ " " + Integer.toString((NodeCapture.framesAleatorios-framesAleatorios) * 100/(NodeCapture.framestotales-framestotales) )+"%");
				NodeCapture.Print("Enviados                :" + Long.toString(NodeCapture.messagesSend-messagesSend) + " " + Long.toString((NodeCapture.messagesSend-messagesSend) * 100/(NodeCapture.framestotales-framestotales) )+"%");
				NodeCapture.Print("===========================================================");
				
				framestotales = NodeCapture.framestotales;
				framesdescartados = NodeCapture.framesdescartados;
				framesNoFromMAC = NodeCapture.framesNoFromMAC;
				framesNoRSSI = NodeCapture.framesNoRSSI;
				framesAleatorios = NodeCapture.framesAleatorios;
				messagesSend = NodeCapture.messagesSend;
			}
		}
	}
	
	
	public static boolean isBetween(int x, int lower, int upper) {
		  return lower <= x && x <= upper;
	}
	
}
