package com.kiribuki.nodecapture;

import com.kiribuki.nodecapture.IEEE802dot11_RADIOTAP;
import com.kiribuki.nodecapture.IEEE802dot11_RADIOTAP.DataField_DBM_ANTENNA_SIGNAL;
import com.kiribuki.nodecapture.SendPacketCapture;

import java.util.ArrayList;  
import java.util.List;  

import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapIf;  
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;  

import com.kiribuki.packetcapture.PacketCapture;

import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;


public class NodeCapture {
	
	static byte[] nodeMAC;
	static float longitud=0;
	static float latitud=0;
	static int lenMAC=6;
	static int fromPunter = 0;
	static int toPunter = 0;
	static int BSSIDPunter = 0;

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		
	    int numDis=-1;
	    String dispositivo;
	    String QueueName;
	  
	    
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
		
		/************* Registar del radiotap!!! ************/
		try {
			int headerID = JRegistry.register(IEEE802dot11_RADIOTAP.class);
			System.out.printf("Header registrado con éxtio, su ID es %d\n", headerID); 
		} catch (RegistryHeaderErrors e) {  
			  e.printStackTrace();  
			  System.exit(1);  
		}  
		//Miramos los Headers que estan registrados
		System.out.println(JRegistry.toDebugString());
		/**************** Final del registro del Radiotap ***************/
		
		
		
		
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
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
  
        // Agafem el dispositiu que volem
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "Descripción no disponible";
            if (dispositivo.equals(device.getName().toString())) {
            	System.out.println("Encontrado");
            	numDis = i;
            	nodeMAC = device.getHardwareAddress();
            }
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
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
        //PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
        PcapPacketHandler<SendPacketCapture> jpacketHandler = new PcapPacketHandler<SendPacketCapture>() { 
  
            public void nextPacket(PcapPacket packet, SendPacketCapture sendpacketcapture) {  
  
            	IEEE802dot11_RADIOTAP radiotap = new IEEE802dot11_RADIOTAP();
            	DataField_DBM_ANTENNA_SIGNAL RSSI = new DataField_DBM_ANTENNA_SIGNAL();
            	
            	int punter;
            	// Si detectamos el header radiotap, extaremos los datos y enviamos el paquete a la cola
            	if (packet.hasHeader(radiotap)) {
            		//System.out.printf("Longitud capçalera: %d\n",radiotap.len());
            		// punter, determina la longitud del Header Radiotap.Inmediatamente después 
            		// esta situado el frame 802.11
            		punter = radiotap.len();
            		            		
            		PacketCapture packetcapture = new PacketCapture();
            		// Carga de los datos del paquete en el objeto packetcapture
            		packetcapture.SetFechaCaptura(packet.getCaptureHeader().timestampInMillis());
               	 	packetcapture.Setwirelen(packet.getCaptureHeader().wirelen());
            		packetcapture.SetNodeMAC(FormatUtils.mac(nodeMAC));
            		packetcapture.SetLongitud(longitud);
            		packetcapture.SetLatitud(latitud);
            		
            		if ((radiotap.present_AntennaSignal()==1) && (radiotap.hasSubHeader(RSSI)==true)) {
            			packetcapture.SetRSSI(RSSI.DBM_ANTENNA_SIGNAL());
            		}
            		
            		packetcapture.SetTipoFrame(packet.getByte(punter));
            		
            		byte[] FrameControl = packet.getByteArray(punter, 2);
            		
            		
            		
            		
            		
            		if (punter + 4 + 3*lenMAC <= packet.getCaptureHeader().wirelen() ) {
            			System.out.printf("%s %s %s\n", 
            				    FormatUtils.mac(packet.getByteArray(punter + 4, lenMAC)),
            				    		FormatUtils.mac(packet.getByteArray((punter + lenMAC + 4), lenMAC)), 
            				    				FormatUtils.mac(packet.getByteArray((punter + 2 * lenMAC + 4 ), lenMAC)));
            		}
            		
            		
            		
            		
            		if (PunterosDirecciones(punter, FrameControl )) {
            			if (fromPunter > 0) {
            				packetcapture.SetToMAC(FormatUtils.mac(packet.getByteArray(toPunter,lenMAC)));
            			}
    					if (toPunter > 0) {
    						packetcapture.SetfromMAC(FormatUtils.mac(packet.getByteArray(fromPunter,lenMAC)));
    					}
    					if (BSSIDPunter > 0) {
    						packetcapture.SetBSSID(FormatUtils.mac(packet.getByteArray(BSSIDPunter,lenMAC)));
            			}
            		}
               	 	packetcapture.SetSignalHash(packet.getByteArray(punter, packet.getCaptureHeader().wirelen()-punter));           	 
               	 	sendpacketcapture.Send(packetcapture);
            	}
            }  
        };
       
        SendPacketCapture sendpacketcapture = new SendPacketCapture();
        sendpacketcapture.SetQueueName(QueueName);
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, sendpacketcapture);    
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
        System.out.println(sb.toString());
		
		
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
					case "1000":	
					case "1001":
					case "1011":
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
						fromPunter = offset;
						toPunter = 0;
						BSSIDPunter = 0;
						break;
					// Contention-Free (CF-End)
					// CF-End + CF-Ack
					case "1110":
					case "1111":
						fromPunter = 0;
						toPunter = offset;
						BSSIDPunter = offset + 1 * lenMAC;
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
				System.out.printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! DS: %s\n", Integer.toBinaryString(DS));
				switch (Integer.toBinaryString(DS)) {
					//IBSS (ad-hoc)
					case "0":
						fromPunter = offset;
						toPunter = offset  + 1 * lenMAC;
						BSSIDPunter = offset + 2 * lenMAC;
						break;
					// Hacia AP (Infraestructura)
					case "1":
						//fromPunter = offset + 1 * lenMAC;
						//toPunter = offset + 2 * lenMAC;
						//BSSIDPunter = offset;
						fromPunter = offset + 1 * lenMAC;
						toPunter = offset;
						BSSIDPunter = offset + 2 * lenMAC;
						break;
					// Desde AP (Infraestructura)
					case "10":
						//fromPunter = offset + 2 * lenMAC;
						//toPunter = offset;
						//BSSIDPunter = offset + 1 * lenMAC;
						fromPunter = offset + 1 * lenMAC;
						toPunter = offset;
						BSSIDPunter = offset + 2 * lenMAC;
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
	
}
