#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define DNS_HEADER_SIZE 12
#define MAX_READ_BUFFER_SIZE 512
#define MAX_WRITE_BUFFER_SIZE 128

struct DNSHeader {
  uint16_t id;

  uint8_t qr;
  uint8_t opcode;
  uint8_t aa;
  uint8_t tc;
  uint8_t rd;

  uint8_t ra;
  uint8_t z;
  uint8_t rcode;

  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

struct DNSQuestion {
  char *qname;
  uint16_t qtype;
  uint16_t qclass;
};

struct DNSResourceRecord {
  char *aname;
  uint16_t atype;
  uint16_t aclass;
  uint32_t attl;
  uint16_t rdlength;
  char *rdata;
};

struct DNSMessage {
  DNSHeader header;
  DNSQuestion *questions;
  DNSResourceRecord *answer;
};

inline uint16_t read_u16(const char *buf) {
  return (static_cast<uint8_t>(buf[0]) << 8) | static_cast<uint8_t>(buf[1]);
}

inline void write_u16(char *buf, uint16_t val) {
  buf[0] = (val >> 8) & 0xFF;
  buf[1] = val & 0xFF;
}

inline void write_u8(char *buf, uint8_t val) { buf[0] = val; }

inline void write_u32(char *buf, uint32_t val) {
  buf[0] = (val >> 24) & 0xFF;
  buf[1] = (val >> 16) & 0xFF;
  buf[2] = (val >> 8) & 0xFF;
  buf[3] = val & 0xFF;
}

class Serializer {
private:
  DNSMessage message;

  void serialize_dns_header(char *buffer) {
    write_u16(buffer, this->message.header.id);

    uint16_t flags = 0;

    flags |= (this->message.header.qr & 0x1) << 15;
    flags |= (this->message.header.opcode & 0xF) << 11;
    flags |= (this->message.header.aa & 0x1) << 10;
    flags |= (this->message.header.tc & 0x1) << 9;
    flags |= (this->message.header.rd & 0x1) << 8;

    flags |= (this->message.header.ra & 0x1) << 7;
    flags |= (this->message.header.z & 0x7) << 4;
    flags |= (this->message.header.rcode & 0xF);

    write_u16(buffer + 2, flags);

    write_u16(buffer + 4, this->message.header.qdcount);
    write_u16(buffer + 6, this->message.header.ancount);
    write_u16(buffer + 8, this->message.header.nscount);
    write_u16(buffer + 10, this->message.header.arcount);
  }

  int serialize_dns_question(const DNSQuestion &question, char *buffer) {
    int question_size = 0;

    char *name = question.qname;
    while (*name) {
      write_u8(buffer++, *name++);
      question_size += 1;
    }

    write_u8(buffer++, 0);
    question_size += 1;

    write_u16(buffer, question.qtype);
    question_size += 2;

    write_u16(buffer + 2, question.qclass);
    question_size += 2;

    return question_size;
  }

  int serialize_dns_answer(const DNSResourceRecord &answer, char *buffer) {
    int answer_size = 0;

    char *name = answer.aname;
    while (*name) {
      write_u8(buffer++, *name++);
      answer_size += 1;
    }

    write_u8(buffer++, 0);
    answer_size += 1;

    write_u16(buffer, answer.atype);
    answer_size += 2;

    write_u16(buffer + 2, answer.aclass);
    answer_size += 2;

    write_u32(buffer + 4, answer.attl);
    answer_size += 4;

    write_u16(buffer + 8, answer.rdlength);
    answer_size += 2;

    memcpy(buffer + 10, answer.rdata, answer.rdlength);
    answer_size += answer.rdlength;

    return answer_size;
  }

public:
  Serializer(DNSMessage message) { this->message = message; }

  void serialize_dns_message(char *buffer) {
    serialize_dns_header(buffer);

    char *question_ptr = buffer + DNS_HEADER_SIZE;

    for (int i = 0; i < this->message.header.qdcount; i++) {
      question_ptr +=
          serialize_dns_question(this->message.questions[i], question_ptr);
    }

    char *answer_ptr = question_ptr;

    for (int i = 0; i < this->message.header.ancount; i++) {
      answer_ptr += serialize_dns_answer(this->message.answer[i], answer_ptr);
    }
  }
};

class Deserializer {
private:
  char *buffer;

public:
  Deserializer(char *buffer) { this->buffer = buffer; }

  DNSHeader parse_dns_header() {
    DNSHeader header{};

    header.id = read_u16(this->buffer);

    uint16_t flags = read_u16(this->buffer + 2);

    header.qr = (flags >> 15) & 1;
    header.opcode = (flags >> 11) & 0xF;
    header.aa = (flags >> 10) & 1;
    header.tc = (flags >> 9) & 1;
    header.rd = (flags >> 8) & 1;
    header.ra = (flags >> 7) & 1;
    header.z = (flags >> 4) & 0x7;
    header.rcode = flags & 0xF;

    header.qdcount = read_u16(this->buffer + 4);
    header.ancount = read_u16(this->buffer + 6);
    header.nscount = read_u16(this->buffer + 8);
    header.arcount = read_u16(this->buffer + 10);

    return header;
  }

  DNSQuestion *parse_dns_questions(uint16_t count) {
    DNSQuestion *questions = new DNSQuestion[count];

    char *buffer = this->buffer + DNS_HEADER_SIZE;

    for (uint16_t i = 0; i < count; i++) {
      questions[i].qname = buffer;
      buffer += strlen(buffer) + 1;
      questions[i].qtype = read_u16(buffer);
      buffer += 2;
      questions[i].qclass = read_u16(buffer);
      buffer += 2;
    }

    return questions;
  }
};

DNSResourceRecord *generate_dns_answers(DNSQuestion *questions,
                                        uint16_t count) {
  DNSResourceRecord *answers = new DNSResourceRecord[count];

  for (uint16_t i = 0; i < count; i++) {
    answers[i].aname = questions[i].qname;
    answers[i].atype = questions[i].qtype;
    answers[i].aclass = questions[i].qclass;
    answers[i].attl = 3600;
    answers[i].rdlength = 4;
    answers[i].rdata = new char[4];
    write_u32(answers[i].rdata, 8 << 24 | 8 << 16 | 8 << 8 | 8); // 8.8.8.8
  }

  return answers;
}

DNSHeader build_response_header(DNSHeader request_header) {
  DNSHeader response_header{};

  response_header.id = request_header.id;
  response_header.qr = 1;
  response_header.opcode = request_header.opcode;
  response_header.aa = 0;
  response_header.tc = 0;
  response_header.rd = request_header.rd;

  response_header.ra = 0;
  response_header.z = 0;

  if (request_header.opcode == 0) {
    response_header.rcode = 0;
  } else {
    response_header.rcode = 4;
  }

  response_header.qdcount = request_header.qdcount;
  response_header.ancount = request_header.qdcount;
  response_header.nscount = 0;
  response_header.arcount = 0;

  return response_header;
}

int main() {
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;

  setbuf(stdout, NULL);

  int udp_socket;
  struct sockaddr_in client_address;

  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_socket == -1) {
    std::cerr << "Socket creation failed: " << strerror(errno) << "..."
              << std::endl;

    return 1;
  }

  int reuse = 1;
  if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) <
      0) {
    std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;

    return 1;
  }

  sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(2053),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(udp_socket, reinterpret_cast<struct sockaddr *>(&serv_addr),
           sizeof(serv_addr)) != 0) {
    std::cerr << "Bind failed: " << strerror(errno) << std::endl;

    return 1;
  }

  int bytes_read;
  char buffer[MAX_READ_BUFFER_SIZE];

  socklen_t client_addr_len = sizeof(client_address);

  while (true) {
    bytes_read = recvfrom(udp_socket, buffer, sizeof(buffer), 0,
                          reinterpret_cast<struct sockaddr *>(&client_address),
                          &client_addr_len);
    if (bytes_read == -1) {
      perror("Error receiving data");

      break;
    }

    std::cout << "Received " << bytes_read << " bytes from client" << std::endl;

    Deserializer *d = new Deserializer(buffer);

    DNSHeader request_header = d->parse_dns_header();
    DNSHeader response_header = build_response_header(request_header);

    DNSQuestion *questions = d->parse_dns_questions(request_header.qdcount);

    DNSResourceRecord *answers =
        generate_dns_answers(questions, request_header.qdcount);

    DNSMessage message{};
    message.header = response_header;
    message.questions = questions;
    message.answer = answers;

    char response[128];

    Serializer *s = new Serializer(message);

    s->serialize_dns_message(response);

    if (sendto(udp_socket, response, sizeof(response), 0,
               reinterpret_cast<struct sockaddr *>(&client_address),
               sizeof(client_address)) == -1) {
      perror("Failed to send response");
    } else {
      std::cout << "Sent " << sizeof(response) << " bytes to client"
                << std::endl;
    }

    delete s;
    delete answers;
    delete questions;
    delete d;
  }

  close(udp_socket);

  return 0;
}
