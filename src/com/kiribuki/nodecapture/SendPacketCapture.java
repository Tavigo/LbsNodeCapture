package com.kiribuki.nodecapture;

import com.google.gson.Gson;

import com.kiribuki.queueservice.QueueService;
import com.kiribuki.packetcapture.PacketCapture;

public class SendPacketCapture {
	
	private String lclQueueName;
	private QueueService qs;
	private int contador = 0;
	private int avis = 0;
	
	public void SetQueueName(String QueueName) throws Exception {
		lclQueueName = QueueName;
		qs = new QueueService();
		if (qs.CreateQueue(lclQueueName) == false ) {
			System.out.println("Error creando la cola!!!");
			System.exit(1); 
		}
	}
	
	public boolean Send(PacketCapture packetcapture) {
		Gson gson = new Gson();
		String json = gson.toJson(packetcapture);
		
		contador+=1;
		avis +=1;
		
		if (avis >= 10 ) {
			avis =0;
			System.out.println(json);
			System.out.printf("FRAMES: %d", contador);
		}
		
		
		if (qs.SendMessage(json) == false ) {
			System.out.println("Error enviando mensaje!!!");
			//System.exit(1);
			try {
				SetQueueName(lclQueueName);
			} catch (Exception e) {
				System.out.println(e.toString());
			}
		}
	
		return true;
	}
}
