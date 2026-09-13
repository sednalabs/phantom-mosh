// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "session_offer.h"
#include <iostream>
#include <stdexcept>
#include <type_traits>
#include <utility>
using namespace phantom;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while(false)
void invalid(std::string_view input) {
  SessionOfferDecoder d;
  try {d.feed(input); d.finish(); throw std::runtime_error("invalid offer accepted");}
  catch(const Error& e) { CHECK(std::string_view(e.what())=="invalid session offer"); }
  try {d.feed({}); throw std::runtime_error("poisoned decoder reused");} catch(const Error&) {}
}
int main() {
  try {
    static_assert(!std::is_copy_constructible_v<SessionFrame>);
    auto key=Bootstrap::parse("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
    for(auto ip:{"127.0.0.1","2001:db8::1","ffff:eeee:dddd:cccc:bbbb:aaaa:9999:8888"}) {
      // The last address is multicast and must not be used even in an offer.
      if(ip[0]=='f') { try {UdpEndpoint::parse(ip,60000); throw std::runtime_error("multicast accepted");} catch(const Error&) {} continue; }
      auto e=UdpEndpoint::parse(ip,65535); auto f=make_session_offer(e,key);
      for(std::size_t split=0;split<=f.view().size();++split) {
        SessionOfferDecoder d; d.feed(f.view().substr(0,split)); d.feed(f.view().substr(split));
        auto offer=d.finish(); CHECK(offer.server==e); CHECK(make_session_offer(offer.server,offer.secret).view()==f.view());
      }
      std::string wire(f.view());
      for(std::size_t n=0;n<wire.size();++n) invalid(std::string_view(wire).substr(0,n));
      invalid("banner\n"+wire); invalid(wire+"x"); invalid(wire+wire);
      auto changed=wire;changed.replace(changed.find("session/draft-01"),16,"session/draft-02");invalid(changed);
      changed=wire;changed.replace(changed.find("server client"),13,"client server");invalid(changed);
      changed=wire;changed.replace(changed.find("65535"),5,"065535");invalid(changed);
      changed=wire;changed.replace(changed.find(ip),std::string(ip).size(),"host.example");invalid(changed);
      changed=wire;changed.back()='\r';invalid(changed);
      auto moved=std::move(f);CHECK(f.view().empty());moved.clear();CHECK(moved.view().empty());
    }
    invalid(std::string(SESSION_OFFER_MAX+1,'A'));
    std::cout<<"PASS endpoint-bound offers, every split/truncation, canonical input, profiles and secret ownership\n";return 0;
  }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
