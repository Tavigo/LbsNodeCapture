package com.kiribuki.nodecapture;

import com.kiribuki.nodecapture.SendPacketCapture;

import java.util.ArrayList;  
import java.util.Date;  
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
            .printf("\nDevice escogifo '%s'\n",  
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
            	/*
                System.out.printf("Received packet at %s caplen=%-4d wirelen=%-4d\n",  
                    new Date(packet.getCaptureHeader().timestampInMillis()),   
                    packet.getCaptureHeader().caplen(),  // Length actually captured  
                    packet.getCaptureHeader().wirelen() // Original length   
                    );
               */
           	 
            	 PacketCapture packetcapture = new PacketCapture(); 
  	 
            	  // Carga de los datos del paquete en el objeto packetcapture
            	 packetcapture.SetFechaCaptura(new Date(packet.getCaptureHeader().timestampInMillis()));
            	 packetcapture.SetNodeMAC(FormatUtils.mac(nodeMAC));
            	 packetcapture.SetLongitud(longitud);
            	 packetcapture.SetLatitud(latitud);
             	 if (packet.getCaptureHeader().wirelen() > 34 ) {
             		 packetcapture.SetfromMAC(FormatUtils.mac(packet.getByteArray(28,6)));
             		 packetcapture.SetToMAC(FormatUtils.mac(packet.getByteArray(22,6)));
             	 }
             	 packetcapture.SetSignalHash(packet.getByteArray(18, packet.getCaptureHeader().wirelen()-18));
            	 packetcapture.SetRSSI(packet.getByte(14));		
            	 sendpacketcapture.Send(packetcapture);
            	 packet.getCaptureHeader();
            }  
        };  
       
        SendPacketCapture sendpacketcapture = new SendPacketCapture();
        sendpacketcapture.SetQueueName(QueueName);
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, sendpacketcapture);    
        pcap.close();
		
	}
	
}
