package com.kiribuki.nodecapture;

import com.google.gson.Gson;

import com.kiribuki.queueservice.QueueService;
import com.kiribuki.packetcapture.PacketCapture;

public class SendPacketCapture {
	
	private String lclQueueName;
	private QueueService qs;
	
	public void SetQueueName(String QueueName) throws Exception {
		lclQueueName = QueueName;
		qs = new QueueService();
		if (qs.CreateQueue(lclQueueName) == false ) {
			System.out.println("Error creando la cola!!!");
			System.exit(1); 
		}
	}
	
	public boolean Send(PacketCapture packetcapture){
		Gson gson = new Gson();
		String json = gson.toJson(packetcapture);
		
		System.out.println(json);
	
		if (qs.SendMessage(json) == false ) {
			System.out.println("Error enviando mensaje!!!");
			System.exit(1); 
		}
	
		return true;
	}
}
