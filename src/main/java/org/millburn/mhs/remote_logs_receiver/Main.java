package org.millburn.mhs.remote_logs_receiver;

import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.fluent.SnmpBuilder;
import org.snmp4j.fluent.SnmpCompletableFuture;
import org.snmp4j.fluent.TargetBuilder;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class Main {
    private Snmp snmp;

    public Main(String address, int port, boolean useTCP, int numThreads, String securityName, String authPassphrase, String privPassphrase, String contextName, String... oids) throws IOException {
        SnmpBuilder snmpBuilder = new SnmpBuilder();

        if(useTCP) {
            this.snmp = snmpBuilder.tcp(new TcpAddress(InetAddress.getByName(address), port)).v3().usm().threads(numThreads).build();
        }

        if(!useTCP) {
            this.snmp = snmpBuilder.udp(new UdpAddress(InetAddress.getByName(address), port)).v3().usm().threads(numThreads).build();
        }

        this.snmp.listen();
        Address targetAddress = GenericAddress.parse(address);
        byte[] targetEngineID = snmp.discoverAuthoritativeEngineID(targetAddress, 1000);
        if (targetEngineID != null) {
            TargetBuilder<?> targetBuilder = snmpBuilder.target(targetAddress);
            Target<?> userTarget = targetBuilder
                    .user(securityName, targetEngineID)
                    .auth(TargetBuilder.AuthProtocol.hmac192sha256).authPassphrase(authPassphrase)
                    .priv(TargetBuilder.PrivProtocol.aes128).privPassphrase(privPassphrase)
                    .done()
                    .timeout(500).retries(1)
                    .build();

            PDU pdu = targetBuilder.pdu().type(PDU.GETNEXT).oids(oids).contextName(contextName).build();
            SnmpCompletableFuture snmpRequestFuture = SnmpCompletableFuture.send(snmp, userTarget, pdu);
            try {
                List<VariableBinding> vbs = snmpRequestFuture.get().getAll();

                System.out.println("Received: " + snmpRequestFuture.getResponseEvent().getResponse());
                System.out.println("Payload:  " + vbs);
            } catch (ExecutionException | InterruptedException ex) {
                if (ex.getCause() != null) {
                    System.err.println(ex.getCause().getMessage());
                } else {
                    System.err.println("Request failed: "+ex.getMessage());
                }
            }
        }
        else {
            System.err.println("Timeout on engine ID discovery for "+targetAddress+", GETNEXT not sent.");
        }
        snmp.close();

    }

    public static void main(String[] args) {

    }
}
