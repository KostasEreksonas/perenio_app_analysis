#!/usr/bin/env python3

import wave
import array
from scapy.all import PcapReader, IP, UDP

class Stream(object):
    """Filter packet capture data for RTP packets and parse them into separate audio / video streams"""
    def __init__(self):
        self.audio_port = 50612
        self.video_port = 54386
        self.capture_file = "capture.pcap"
        self.audioBuffer = bytearray()
        self.nalBuffer = bytearray()
        self.videoBuffer = bytearray()
        self.audioInfo = {
            "version": [],
            "padding": [],
            "extension": [],
            "csrcCount": [],
            "marker": [],
            "type": [],
            "sequenceNumber": [],
            "timestamp": [],
            "ssrcIdentifier": [],
            "payload": []
        }
        self.videoInfo = {
            "version": [],
            "padding": [],
            "extension": [],
            "csrcCount": [],
            "marker": [],
            "type": [],
            "sequenceNumber": [],
            "timestamp": [],
            "ssrcIdentifier": [],
            "payload": {
                "fuIdentifier": {
                    "fBit": [],
                    "nri": [],
                    "nalUnitType_I": [],
                    "fullIdentifier": []
                },
                "fuHeader": {
                    "startBit": [],
                    "endBit": [],
                    "reservedBit": [],
                    "nalUnitType_H": [],
                    "fullHeader": []
                },
                "isFragment": [],
                "data": []
            }
        }

    def parseRTPHeader(self, data):
        """
        Parse fixed RTP header
        CSRC Count (CC) and Extension (X) header bits were observed to be 0 for Peifc01 IP camera
        CSRC byte and extension data parsing is not accounted for
        This does not account for CSRC bytes because all observed RTP packets for Peifc01 IP camera had extension bit set to 0
        """
        version = int(data[0] >> 6)
        padding = True if (data[0] >> 5) & 1 else False
        extension = True if (data[0] >> 4) & 1 else False
        csrc_count = data[0] & 0b00001111
        marker = (data[1] >> 7) & 1
        type = "16-bit uncompressed audio" if data[1] & 0b01111111 == 11 else "Video (DynamicRTP-Type-96)" if data[1] & 0b01111111 == 96 else "Unknown"
        sequence_number = data[2]
        sequence_number = sequence_number << 8
        sequence_number |= data[3]
        timestamp = data[4]
        timestamp = timestamp << 8
        timestamp |= data[5]
        timestamp = timestamp << 8
        timestamp |= data[6]
        timestamp = timestamp << 8
        timestamp |= data[7]
        ssrc_identifier = data[8]
        ssrc_identifier = ssrc_identifier << 8
        ssrc_identifier |= data[9]
        ssrc_identifier = ssrc_identifier << 8
        ssrc_identifier |= data[10]
        ssrc_identifier = ssrc_identifier << 8
        ssrc_identifier |= data[11]
        payload = data[12:]

        return version, padding, extension, csrc_count, marker, type, sequence_number, timestamp, ssrc_identifier, payload

    def fragmentationUnitIndicator(self, indicator):
        """Parse Fragmentation Unit (FU) Identifier and Header bytes"""
        fBit = (indicator >> 7) & 1
        nri = (indicator >> 5) & 0b11
        nalUnitType_I = indicator & 0b00011111

        return fBit, nri, nalUnitType_I

    def fragmentationUnitHeader(self, header):
        startBit = (header >> 7) & 1
        endBit = (header >> 6) & 1
        reservedBit = (header >> 5) & 1
        nalUnitType_H = header & 0b00011111

        return startBit, endBit, reservedBit, nalUnitType_H

    def collectStreams(self):
        """
        Filter capture file for RTP packets
        Parse packets containing audio and video stream data into separate dicts
        """
        with PcapReader(self.capture_file) as capture:
            for packet in capture:
                if UDP not in packet:
                    continue

                udpPacket = packet[UDP]
                version, padding, extension, csrcCount, marker, type, sequenceNumber, timestamp, ssrcIdentifier, payload = self.parseRTPHeader(bytes(udpPacket.payload))
                if udpPacket.sport == self.audio_port:
                    self.audioInfo['version'].append(version)
                    self.audioInfo['padding'].append(padding)
                    self.audioInfo['extension'].append(extension)
                    self.audioInfo['csrcCount'].append(csrcCount)
                    self.audioInfo['marker'].append(marker)
                    self.audioInfo['type'].append(type)
                    self.audioInfo['ssrcIdentifier'].append(ssrcIdentifier)
                    self.audioInfo['timestamp'].append(timestamp)
                    self.audioInfo['sequenceNumber'].append(sequenceNumber)
                    self.audioInfo['payload'].append(payload)
                elif udpPacket.sport == self.video_port:
                    self.videoInfo['version'].append(version)
                    self.videoInfo['padding'].append(padding)
                    self.videoInfo['extension'].append(extension)
                    self.videoInfo['csrcCount'].append(csrcCount)
                    self.videoInfo['marker'].append(marker)
                    self.videoInfo['type'].append(type)
                    self.videoInfo['ssrcIdentifier'].append(ssrcIdentifier)
                    self.videoInfo['timestamp'].append(timestamp)
                    self.videoInfo['sequenceNumber'].append(sequenceNumber)
                
                    # First byte (payload[0]) - FU Identifier
                    # Second byte (payload[1]) - FU Header
                    fBit, nri, nalUnitType_I = self.fragmentationUnitIndicator(payload[0])
                    self.videoInfo['payload']['fuIdentifier']['fBit'].append(fBit)
                    self.videoInfo['payload']['fuIdentifier']['nri'].append(nri)
                    self.videoInfo['payload']['fuIdentifier']['nalUnitType_I'].append(nalUnitType_I)
                    self.videoInfo['payload']['fuIdentifier']['fullIdentifier'].append(payload[0])
                    if nalUnitType_I == 28:
                        startBit, endBit, reservedBit, nalUnitType_H = self.fragmentationUnitHeader(payload[1])
                        self.videoInfo['payload']['fuHeader']['startBit'].append(startBit)
                        self.videoInfo['payload']['fuHeader']['endBit'].append(endBit)
                        self.videoInfo['payload']['fuHeader']['reservedBit'].append(reservedBit)
                        self.videoInfo['payload']['fuHeader']['nalUnitType_H'].append(nalUnitType_H)
                        self.videoInfo['payload']['fuHeader']['fullHeader'].append(payload[1])
                        self.videoInfo['payload']['isFragment'].append(True)
                        self.videoInfo['payload']['data'].append(payload[2:])
                    elif nalUnitType_I == 29:
                        pass
                    else:
                        self.videoInfo['payload']['fuHeader']['startBit'].append("")
                        self.videoInfo['payload']['fuHeader']['endBit'].append("")
                        self.videoInfo['payload']['fuHeader']['reservedBit'].append("")
                        self.videoInfo['payload']['fuHeader']['nalUnitType_H'].append("")
                        self.videoInfo['payload']['fuHeader']['fullHeader'].append("")
                        self.videoInfo['payload']['isFragment'].append(False)
                        self.videoInfo['payload']['data'].append(payload)

    def unwrapSequenceNumber(self, sequence):
        """
        Sequence number is a 16-bit long value that can represent unsigned integers in the range of 0 - 65,535.
        If the value of sequence number header field exceeds 65,535, it wraps back to zero.
        """
        unwrapped = []
        wraps = 0 # Increase by 1 on every (0 -> 65536 unwrap)
        previous = sequence[0]
        for i, current in enumerate(sequence):
            if i > 0:
                if previous - current > 32768:
                    wraps += 1
            unwrapped.append(current + wraps * 65536)
            previous = current

        return unwrapped

    def reorder(self, data, sortedIndices):
        return [data[i] for i in sortedIndices]

    def sortVideoIndices(self):
        """
        Sort indices of out-of-order RTP packets, containing NAL units
        Sort by timestamp first, if multiple packets have the same timestamp, sort by sequence number
        """
        packetCount = len(self.videoInfo["sequenceNumber"])
        unwrappedSequence = self.unwrapSequenceNumber(self.videoInfo['sequenceNumber'])
        return sorted(range(packetCount), key=lambda i: (self.videoInfo["timestamp"][i], unwrappedSequence[i]))

    def sortVideoPackets(self):
        """Sort out-of-order RTP packets, containing NAL units"""
        sortedIndices = self.sortVideoIndices()
        for key in ["version", "padding", "extension", "csrcCount", "marker", "type", "sequenceNumber", "timestamp", "ssrcIdentifier"]:
            self.videoInfo[key] = self.reorder(self.videoInfo[key], sortedIndices)
        fuId = self.videoInfo["payload"]["fuIdentifier"]
        for key in ["fBit", "nri", "nalUnitType_I", "fullIdentifier"]:
            fuId[key] = self.reorder(fuId[key], sortedIndices)
        fuHeader = self.videoInfo['payload']['fuHeader']
        for key in ["startBit", "endBit", "reservedBit", "nalUnitType_H", "fullHeader"]:
            fuHeader[key] = self.reorder(fuHeader[key], sortedIndices)
        self.videoInfo["payload"]["isFragment"] = self.reorder(self.videoInfo["payload"]["isFragment"], sortedIndices)
        self.videoInfo["payload"]["data"] = self.reorder(self.videoInfo["payload"]["data"], sortedIndices)

    def sortAudioIndices(self):
        """
        Sort indices of out-of-order RTP packets, containing audio data
        Sort by timestamp first, if multiple packets have the same timestamp, sort by sequence number
        """
        packetCount = len(self.audioInfo["sequenceNumber"])
        unwrappedSequence = self.unwrapSequenceNumber(self.audioInfo['sequenceNumber'])
        return sorted(range(packetCount), key=lambda i: (self.audioInfo["timestamp"][i], unwrappedSequence[i]))

    def sortAudioPackets(self):
        """Sort out-of-order RTP packets, containing NAL units"""
        sortedIndices = self.sortAudioIndices()
        for key in ["version", "padding", "extension", "csrcCount", "marker", "type", "sequenceNumber", "timestamp", "ssrcIdentifier", "payload"]:
            self.audioInfo[key] = self.reorder(self.audioInfo[key], sortedIndices)

    def keepIndices(self, info):
        """Keep indices of non-duplicate RTP packets only"""
        seq = info['sequenceNumber']
        return [i for i in range(len(seq)) if i == 0 or seq[i] != seq[i-1]]

    def removeDuplicates(self, media):
        """Remove duplicated RTP packets"""
        if media == "video":
            indicesToKeep = self.keepIndices(self.videoInfo)
            for key in ["version", "padding", "extension", "csrcCount", "marker", "type", "sequenceNumber", "timestamp", "ssrcIdentifier"]:
                self.videoInfo[key] = self.reorder(self.videoInfo[key], indicesToKeep)
            payload = self.videoInfo['payload']
            for key in ["fBit", "nri", "nalUnitType_I", "fullIdentifier"]:
                payload['fuIdentifier'][key] = self.reorder(payload['fuIdentifier'][key], indicesToKeep)
            for key in ["startBit", "endBit", "reservedBit", "nalUnitType_H", "fullHeader"]:
                payload['fuHeader'][key] = self.reorder(payload['fuHeader'][key], indicesToKeep)
            payload['isFragment'] = self.reorder(payload['isFragment'], indicesToKeep)
            payload['data'] = self.reorder(payload['data'], indicesToKeep)
        elif media == "audio":
            indicesToKeep = self.keepIndices(self.audioInfo)
            for key in self.audioInfo:
                self.audioInfo[key] = self.reorder(self.audioInfo[key], indicesToKeep)

    def collectVideoStream(self):
        """
        Reassemble Fragmentation Units A (FU-A) into NAL units (NALUs)
        Sequentially collect reassembled FU-A and single-packet NALUs into a video stream
        """
        for i in range(len(self.videoInfo['sequenceNumber'])):
            if not self.videoInfo['payload']['isFragment'][i]:
                # complete NALU already — emit immediately, independent of any FU state
                self.videoBuffer += b'\x00\x00\x00\x01' + bytes(self.videoInfo['payload']['data'][i])
                continue

            startBit = self.videoInfo['payload']['fuHeader']['startBit'][i]
            endBit = self.videoInfo['payload']['fuHeader']['endBit'][i]
            if startBit == 1:
                # Flush NAL buffer
                self.nalBuffer = bytearray()
                # Construct NAL header
                nalHeader = (self.videoInfo['payload']['fuIdentifier']['fullIdentifier'][i] & 0xE0) | (self.videoInfo['payload']['fuHeader']['fullHeader'][i] & 0x1F)
                self.nalBuffer += b'\x00\x00\x00\x01'
                self.nalBuffer += int.to_bytes(nalHeader, 1, 'big')
                self.nalBuffer += bytes(self.videoInfo['payload']['data'][i])
            if endBit == 1:
                self.nalBuffer += bytes(self.videoInfo['payload']['data'][i]) if not startBit else b''
                self.videoBuffer += self.nalBuffer
            elif not startBit:
                self.nalBuffer += bytes(self.videoInfo['payload']['data'][i])

    def collectAudioStream(self):
        """
        Collect RTP L16 packets - raw 16-bit signed PCM big-endian data
        Reverse endianness to save data as .wav file
        """
        for i in range(len(self.audioInfo['sequenceNumber'])):
            sample = array.array("h", bytes(self.audioInfo['payload'][i]))
            sample.byteswap()
            self.audioBuffer += sample

    def saveVideoStream(self):
        """Export video buffer as H.264 video file"""
        with open("video.h264", "wb") as videoFile:
            videoFile.write(self.videoBuffer)

    def saveAudioStream(self):
        """Save audio stream as Waveform Audio File"""
        with wave.open("audio.wav", "wb") as audioFile:
            audioFile.setnchannels(1)
            audioFile.setsampwidth(2)
            audioFile.setframerate(44100)
            audioFile.writeframes(self.audioBuffer)


def main():
    stream = Stream()

    stream.collectStreams()

    stream.sortVideoPackets()
    stream.removeDuplicates("video")
    stream.collectVideoStream()
    stream.saveVideoStream()
    
    stream.sortAudioPackets()
    stream.removeDuplicates("audio")
    stream.collectAudioStream()
    stream.saveAudioStream()

if __name__ == "__main__":
    main()