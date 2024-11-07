#!/usr/bin/env python3

'''
기본 IPv4 라우터 (정적 라우팅) in Python.
'''

import time
import queue
import switchyard
import logging
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from collections import deque

# ARP 요청의 최대 시도 횟수
MaxArpTry = 5
# ARP 테이블 항목의 유효 시간(초)
ARPtime = 10.0

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_error(message):
    # 오류 메시지를 로그로 기록
    logging.error(message)

############### 위의 내용은 함수 정의 (로그 설정 등)

class ArpQitem:
    # ARP 큐 항목 정의
    def __init__(self, Dip, intime, port, age=0):
        self.Dip = Dip  # 대상 IP 주소
        self.intime = intime  # 요청 생성 시간
        self.port = port  # 포트 정보
        self.age = age  # ARP 시도 횟수
        self.packets = queue.Queue()  # 대기 중인 패킷을 저장할 큐


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.ARPtime = ARPtime  # ARP 테이블의 유효 시간 설정
        
        # 네트워크 포트 초기화 (IP 주소 -> 이더넷 주소 매핑)
        self.ports = {interface.ipaddr: interface.ethaddr for interface in self.net.interfaces()}
        log_info("Successfully created ports list")
        
        # ARP 테이블 초기화 (ArpT: ip -> mac)
        self.ArpT = dict()
        log_info("Successfully created empty ARP table (ArpT)")
        
        log_info("NOTION: ArpT is unused in lab4 for using cache")

        # 포워딩 테이블 초기화 (FwdT: ip -> (마스크, 다음 홉, 포트))
        self.FwdT = list()
        log_info("Successfully created empty forwarding table (FwdT)")

        # ARP 큐 초기화 (ArpQ: ArpQitem의 큐)
        self.ArpQ = queue.deque()
        log_info("Successfully created empty ARP queue (ArpQ)")

        # 캐시 초기화 (현재 ArpT 대신 사용 중)
        self.cache = dict()
        log_info("Successfully created empty cache")

        # 포워딩 테이블 초기화 함수 호출
        self.initFwdT()


    #####################################################################
    # 시각화 함수

    def showArpT(self):
        # ARP 테이블 표시
        print(f"********** ARP Table **********\n")
        print(f"----ip addr----|----MAC addr----\n")
        for ip, (mac, life) in self.ArpT.items():  # .items() 사용으로 명확성과 효율성 향상
            print(f"{ip}        {mac}:{life}\n")
        print("*********************************\n")

    def showFwdT(self):
        # 포워딩 테이블 표시
        print(f"*********** Forward Table ***********\n")
        print(f"--ip--|--mask--|--next hop--|--port--\n")
        for ip, mask, nexthop, port in self.FwdT:  # FwdT 직접 루프
            print(f"{ip}--{mask}--{nexthop}--{port}\n")
        print("**************************************\n")

    #####################################################################
    # 도움 함수

    def searchArpQ(self, ip):
        # 제너레이터 표현식을 사용해 대상 IP 주소(Dip)가 일치하는 ArpQitem을 찾음
        # 일치하는 항목이 없으면 None을 반환
        return next((item for item in self.ArpQ if item.Dip == ip), None)

    def pickArpQ(self, ip):
        # deque를 사용하여 특정 IP 주소(Dip)와 일치하지 않는 항목을 임시 큐에 추가하여 필터링
        tempQueue = deque(item for item in self.ArpQ if item.Dip != ip)
        # 대상 IP와 일치하는 첫 번째 항목을 찾아 반환
        ret = next((item for item in self.ArpQ if item.Dip == ip), None)
        # self.ArpQ를 tempQueue로 업데이트하여 필터링 완료
        self.ArpQ = tempQueue
        return ret

    def doc2protocol(self, doc):
        # Ethernet 타입 코드에서 문자열 형식의 프로토콜 이름을 반환하는 사전 매핑을 사용
        # doc이 2048일 경우 "IP", 2054일 경우 "ARP" 반환, 그 외에는 "?" 반환
        protocol_map = {
            2048: "IP",
            2054: "ARP"
        }
        return protocol_map.get(doc, "?")


    #####################################################################
    # kernel functions
    
    def initFwdT(self):
    #라우터의 포워딩 테이블(FwdT)을 초기화합니다.
        # 초기 포트 정보 추가: 라우터의 네트워크 인터페이스를 순회하며 포워딩 테이블(FwdT)에 각 포트의 정보 추가
        for port in self.net.interfaces():
            # 포트의 IP 주소, 넷마스크, 다음 홉 주소('0.0.0.0'로 기본값 설정), 포트 이름을 FwdT에 추가
            self.FwdT.append([IPv4Address(port.ipaddr), 
                            IPv4Address(port.netmask), 
                            IPv4Address('0.0.0.0'), 
                            port.name])

        # 포워딩 테이블을 파일에서 읽어와 추가
        try:
            with open("forwarding_table.txt", "r") as ft:
                # 파일의 각 줄을 읽고 분할하여 각 항목을 FwdT에 추가
                for line in ft.readlines():
                    info = line.split()
                    self.FwdT.append([IPv4Address(info[0]), 
                                    IPv4Address(info[1]), 
                                    IPv4Address(info[2]), 
                                    info[3]])
            # 초기화 성공 메시지 로그 기록
            log_info(f"successfully init FwdT")
            self.showFwdT()  # 포워딩 테이블 표시
        except FileNotFoundError:
            # 파일을 찾지 못한 경우 오류 로그 기록
            log_error("forwarding_table.txt not found")
        except Exception as e:
            # 기타 오류가 발생한 경우 오류 로그 기록
            log_error(f"Error initializing forwarding table: {e}")


    def refreshArpT(self):
    #ARP 테이블을 갱신하여 만료된 항목을 삭제합니다.
        current_time = time.time()  # 현재 시간 저장
        ips_to_remove = []  # 삭제할 IP 주소를 저장할 리스트

        # 제거할 항목 식별: ARP 테이블을 순회하여 만료된 항목을 찾음
        for ip, (mac, timestamp) in self.ArpT.items():
            if current_time - timestamp >= self.ARPtime:  # 항목의 유효 기간이 경과한 경우
                ips_to_remove.append(ip)  # 삭제 목록에 추가
                log_info(f"Deleting ARP table entry: {ip}--{mac}")  # 로그에 삭제 메시지 기록

        # 식별된 항목 제거
        for ip in ips_to_remove:
            del self.ArpT[ip]  # ARP 테이블에서 항목 삭제

        # 갱신된 ARP 테이블 로그로 기록 및 표시
        log_info("ARP table successfully refreshed.")
        self.showArpT()  # ARP 테이블 표시


    def processArpQ(self): 
    #대기 중인 ARP 요청들을 처리합니다.
        task_count = len(self.ArpQ)  # 현재 ARP 큐의 작업 개수
        current_index = 0  # 현재 작업 인덱스 초기화
        current_task = self.ArpQ[current_index] if task_count else None  # ARP 큐에서 현재 작업 선택

        # 남아 있는 작업이 있을 때까지 루프
        while task_count > 0:
            # 요청 생성 후 1초 이상 경과했거나 시도 횟수가 0인 경우 (ARP 응답 시간 초과)
            if time.time() - current_task.intime > 1 or current_task.age == 0:
                if current_task.age < MaxArpTry:  # ARP 시도 횟수가 최대 시도 횟수 미만일 때
                    port_info = self.net.interface_by_name(current_task.port)  # 포트 정보 가져오기
                    # ARP 요청 패킷 생성
                    arp_request = create_ip_arp_request(port_info.ethaddr, port_info.ipaddr, current_task.Dip)
                    # ARP 요청 로그 기록
                    log_info(
                        f"Sending ARP request to {current_task.Dip} on port {current_task.port} - Remaining attempts: {MaxArpTry - current_task.age}")
                    
                    # ARP 요청 패킷 전송
                    self.net.send_packet(port_info, arp_request)

                    # 현재 작업 항목의 시도 횟수와 시간을 갱신한 후 큐에 다시 추가
                    updated_task = self.pickArpQ(current_task.Dip)  # ARP 큐에서 현재 작업을 가져옴
                    updated_task.age += 1  # 시도 횟수 증가
                    updated_task.intime = time.time()  # 현재 시간으로 갱신

                    self.ArpQ.append(updated_task)  # 큐에 갱신된 작업 추가
                    current_index -= 1  # 큐에 추가된 작업을 반영하여 인덱스 조정

                else:  # 최대 ARP 시도 횟수에 도달한 경우
                    log_info(f"ARP attempts exhausted for {current_task.Dip}")  # 시도 실패 로그 기록
                    self.pickArpQ(current_task.Dip)  # 큐에서 작업 제거
                    current_index -= 1  # 큐 변경을 반영하여 인덱스 조정

            task_count -= 1  # 남은 작업 수 감소
            current_index += 1  # 인덱스 증가
            # 인덱스가 큐 길이보다 작은 경우 현재 작업 갱신
            current_task = self.ArpQ[current_index] if current_index < len(self.ArpQ) else current_task
        
    #####################################################################

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        # 패킷을 처리하는 함수
        # ARP 또는 IPv4 패킷을 식별하고 적절한 처리 함수로 전달

        _, ifaceName, packet = recv  # recv 패킷에서 인터페이스 이름과 패킷 데이터를 추출
        
        # 유효한 목적지인지 확인
        if not self._is_valid_destination(packet, ifaceName):
            log_info("packet drop: invalid dst")  # 잘못된 목적지 패킷 드롭
            return

        # ARP 패킷인지 확인
        if packet[Ethernet].ethertype == EtherType.ARP:
            self._handle_arp_packet(packet, ifaceName)  # ARP 패킷 처리
        else:
            self._handle_ipv4_packet(packet, ifaceName)  # IPv4 패킷 처리


    def _is_valid_destination(self, packet, iface):
        # 유효한 패킷의 목적지를 확인하는 함수

        dst = packet.get_header(Ethernet).dst  # 이더넷 헤더의 목적지 주소 추출
        # 브로드캐스트 주소이거나, 포트의 이더넷 주소와 일치하는지 확인
        return dst == 'ff:ff:ff:ff:ff:ff' or dst == self.net.interface_by_name(iface).ethaddr


    def _handle_arp_packet(self, packet, iface):
        # ARP 패킷을 처리하는 함수
        
        log_info(f"ARP packet checked\npacket detail:\n{packet}")  # ARP 패킷 정보 로그 기록
        arp = packet.get_header(Arp)  # ARP 헤더 추출
        
        # ARP 패킷이 유효한지 검사
        if not self._validate_arp_packet(arp):
            return
        
        # 대상 IP가 라우터 포트에 있는지 확인
        if arp.targetprotoaddr not in self.ports:
            return

        # ARP 요청이면 요청 처리, 응답이면 응답 처리
        if arp.operation == ArpOperation.Request:
            self._process_arp_request(arp, iface)  # ARP 요청 처리
        else:
            self._process_arp_reply(arp, packet, iface)  # ARP 응답 처리


    def _validate_arp_packet(self, arp):
        # ARP 패킷의 유효성을 검증하는 함수
        
        if not arp:
            log_info("packet drop: empty ARP packet")  # 빈 ARP 패킷 로그
            return False
        return True


    def _process_arp_request(self, arp, iface):
        # ARP 요청을 처리하는 함수
        
        # 송신자의 IP와 MAC 주소를 캐시에 저장
        self.cache[arp.senderprotoaddr] = arp.senderhwaddr
        
        # 응답할 포트를 선택하고 ARP 응답 패킷 생성
        outport = self.net.interface_by_ipaddr(arp.targetprotoaddr)
        reply_packet = create_ip_arp_reply(
            outport.ethaddr,
            arp.senderhwaddr,
            arp.targetprotoaddr,
            arp.senderprotoaddr
        )
        log_info(f"ARP reply packet:\n{reply_packet}\nhas successfully sent to port {iface}")  # ARP 응답 로그
        self.net.send_packet(iface, reply_packet)  # ARP 응답 전송


    def _process_arp_reply(self, arp, packet, iface):
        # ARP 응답을 처리하는 함수
        
        # 응답이 유효한지 확인
        if self._is_invalid_arp_reply(arp, packet, iface):
            log_info("packet drop: invalid ARP packet")  # 유효하지 않은 ARP 패킷 드롭 로그
            return
        
        # 송신자의 IP와 MAC 주소를 캐시에 저장
        self.cache[arp.senderprotoaddr] = arp.senderhwaddr
        
        # 대기 중인 패킷을 전송
        self._forward_queued_packets(arp, iface)


    def _is_invalid_arp_reply(self, arp, packet, iface):
        # ARP 응답의 유효성을 검사하는 함수
        # 송신 또는 대상 MAC 주소가 브로드캐스트이거나, 패킷의 목적지 주소가 인터페이스의 이더넷 주소와 일치하지 않으면 유효하지 않음
        
        return (arp.senderhwaddr == 'ff:ff:ff:ff:ff:ff' or 
                arp.targethwaddr == 'ff:ff:ff:ff:ff:ff' or 
                packet.get_header(Ethernet).dst != self.net.interface_by_name(iface).ethaddr)


    def _forward_queued_packets(self, arp, iface):
        # ARP 응답을 받은 후 대기 중인 패킷을 전송하는 함수
        
        applicant = self.searchArpQ(arp.senderprotoaddr)  # 해당 IP의 ARP 큐 항목 검색
        if not applicant:
            log_info("packet drop: applicant not in ArpQ")  # 대기 중인 항목이 없으면 로그
            return

        # 대기 중인 모든 패킷을 전송
        while not applicant.packets.empty():
            packet = applicant.packets.get()  # 대기 중인 패킷 가져오기
            packet[Ethernet].dst = arp.senderhwaddr  # 목적지 MAC 주소 설정
            log_info(f"applicant in ArpQ: {applicant.Dip}\nhas successfully sent its packet:\n{packet}\n to port {iface}")
            self.net.send_packet(applicant.port, packet)  # 패킷 전송

        self.pickArpQ(arp.senderprotoaddr)  # 큐에서 해당 항목 제거


    def _handle_ipv4_packet(self, packet, iface):
        # IPv4 패킷을 처리하는 함수
        
        protocol = self.doc2protocol(packet[Ethernet].ethertype)  # 패킷의 프로토콜 유형 추출
        log_info(f"{protocol} packet checked\npacket detail:\n{packet}")  # 패킷 세부 정보 로그
        ipv4 = packet.get_header(IPv4)  # IPv4 헤더 추출

        # IPv4 패킷의 유효성 검사
        if not self._validate_ipv4_packet(ipv4, packet):
            return

        # 가장 긴 접두사 일치 항목을 포워딩 테이블에서 찾기
        match_result = self._find_longest_prefix_match(ipv4.dst)
        if not match_result:
            log_info("packet drop: prefix match failed")  # 일치 항목이 없으면 패킷 드롭 로그
            return

        # IPv4 패킷을 전송
        self._forward_ipv4_packet(packet, match_result, ipv4)


    def _validate_ipv4_packet(self, ipv4, packet):
        # IPv4 패킷의 유효성을 검사하는 함수
        
        if not ipv4:
            log_info("packet drop: empty IP packet")  # 빈 IPv4 패킷 드롭 로그
            return False
        if ipv4.dst in self.ports:
            log_info("packet drop: IP packet send to self")  # 자신에게 전송된 패킷 드롭
            return False
        if packet[IPv4].total_length + 14 != packet.size():
            log_info("packet drop: wrong head length, not IPv4 packet")  # 잘못된 패킷 길이 드롭
            return False
        return True


    def _find_longest_prefix_match(self, dst_ip):
        # 포워딩 테이블에서 가장 긴 접두사 일치를 찾는 함수
        
        # 포워딩 테이블에서 일치하는 모든 항목 찾기
        matches = [
            entry for entry in self.FwdT
            if (int(dst_ip) & int(entry[1])) == (int(entry[0]) & int(entry[1]))
        ]
        
        if not matches:
            return None  # 일치 항목이 없으면 None 반환
            
        return max(matches, key=lambda x: int(x[1]))  # 가장 긴 접두사 일치를 반환


    def _forward_ipv4_packet(self, packet, target, ipv4):
        # IPv4 패킷을 전송하는 함수
        
        ip, mask, nexthop, port = target  # 포워딩 대상 정보 추출
        log_info(f"successfully MATCH:\ntarget IP:{ip}\ntarget mask:{mask}\ntarget nexthop:{nexthop}\ntarget port:{port}")
        
        # 다음 홉 설정: '0.0.0.0'이면 패킷의 목적지 IP 사용
        nexthop = ipv4.dst if nexthop == IPv4Address('0.0.0.0') else nexthop
        packet[Ethernet].src = self.net.interface_by_name(port).ethaddr  # 송신 MAC 주소 설정
        packet[IPv4].ttl -= 1  # TTL 값 감소

        # 다음 홉이 캐시에 있는지 확인하고, 있으면 전송, 없으면 ARP 요청 큐에 추가
        if nexthop in self.cache:
            self._send_cached_packet(packet, nexthop, port)
        else:
            self._queue_packet_for_arp(packet, nexthop, port)


    def _send_cached_packet(self, packet, nexthop, port):
        # 캐시에 있는 다음 홉 주소로 패킷을 전송하는 함수
        
        packet[Ethernet].dst = self.cache[nexthop]  # 목적지 MAC 주소를 캐시에서 가져와 설정
        log_info(f"CACHE IT!\npacket NextHop {nexthop} is in cache:\n{nexthop}==>{self.cache[nexthop]}\npacket {packet}\nhas successfully sent to port {port}")
        self.net.send_packet(port, packet)  # 패킷 전송


    def _queue_packet_for_arp(self, packet, nexthop, port):
        # ARP 요청을 통해 다음 홉의 MAC 주소를 찾기 위해 패킷을 큐에 추가하는 함수
        
        log_info(f"ARP to find {nexthop}")  # 다음 홉 찾기 로그
        applicant = self.searchArpQ(nexthop)  # 다음 홉 주소가 이미 ARP 큐에 있는지 확인
        
        # 큐에 있으면 패킷을 대기열에 추가하고, 없으면 새로운 항목을 생성하여 큐에 추가
        if applicant:
            applicant.packets.put(packet)  # 큐에 대기 패킷 추가
        else:
            new_item = ArpQitem(nexthop, time.time(), port, 0)  # 새로운 ARP 큐 항목 생성
            new_item.packets.put(packet)  # 패킷 추가
            self.ArpQ.append(new_item)  # ARP 큐에 항목 추가




    def start(self):
        '''라우터의 동작을 시작하는 데몬.
        패킷을 수신하면서 무한 루프를 돌며, 종료될 때까지 패킷을 처리합니다.
        '''
        while True:
            self.processArpQ()  # ARP 큐를 처리합니다.
            try:
                recv = self.net.recv_packet(timeout=1.0)  # 패킷을 수신합니다. 타임아웃은 1초입니다.
            except NoPackets:
                continue  # 패킷이 없으면 계속 루프를 돌립니다.
            except Shutdown:
                break  # 종료 신호가 오면 루프를 중단합니다.

            log_info(f"get packet at {time.time()}")  # 패킷을 받은 시간을 로그로 기록합니다.
            # ARP 테이블 갱신 (현재는 주석 처리됨)
            # self.refreshArpT()  # ARP 테이블을 갱신합니다.

            # 수신한 패킷을 처리합니다.
            self.handle_packet(recv)
            log_info(f"successfully handle packet\nwait next packet...\n \n")  # 패킷 처리가 완료된 후 로그를 기록합니다.

        self.stop()  # 루프 종료 후 stop() 메서드를 호출하여 네트워크를 종료합니다.

    def stop(self):
        '''네트워크를 종료하는 메서드'''
        self.net.shutdown()  # 네트워크 연결을 종료합니다.


def main(net):
    '''
    라우터의 메인 진입점. Router 객체를 생성하여 동작을 시작합니다.
    '''
    router = Router(net)  # Router 객체를 생성합니다.
    router.start()  # 라우터를 시작합니다.
