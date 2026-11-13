[English](README.md)

# hookprobe

Webhook imzalarını **üretmek**, **doğrulamak**, **yakalamak** ve **yeniden oynamak** için, dış bağımlılığı olmayan küçük bir Go komut satırı aracı.

`hookprobe`, **GitHub**, **Stripe** ve **Slack** imza şemalarının yanı sıra genel bir HMAC kipini (SHA-1 / SHA-256 / SHA-512, hex veya Base64) konuşur. Yerel geliştirme için tasarlanmıştır: sırrınız ve gövdenizin beklenen başlığı üretip üretmediğini kontrol eder, teslimatları kaydeden geçici bir dinleyici ayağa kaldırır ve kaydedilmiş bir yakalamayı makinenizdeki bir servise yeniden gönderir.

## Neden yazıldı

Webhook imza hatalarını ayıklamak zahmetlidir. Gövde doğru görünür, başlık doğru görünür, doğrulayıcı yine de 401 döner — çoğu zaman eksik bir zaman damgası, yanlış imzalanmış dizi veya eskime penceresi yüzünden. `hookprobe` bu kontrolleri açık ve betiklenebilir hale getirir; bir SDK veya üçüncü parti paket indirmez. Her şey Go standart kütüphanesiyle yazılmıştır.

## Özellikler

- GitHub (`X-Hub-Signature-256` / `X-Hub-Signature`), Stripe (`Stripe-Signature` içinde `t=` / `v1=` ve sır rotasyonu), Slack (`v0=` + `X-Slack-Request-Timestamp`) ve genel HMAC özetlerini imzalama ve doğrulama
- Sabit zamanlı karşılaştırma (`crypto/hmac.Equal`) ve yapılandırılabilir zaman damgası toleransı (varsayılan 5 dakika; kontrolü kapatmak için negatif bir süre verin)
- `listen` yerel bir yakalama sunucusu başlatır, sağlayıcıyı başlıklardan otomatik tanır, isteğe bağlı olarak başka bir URL'ye iletir ve yakalamaları diske okunaklı JSON olarak yazar
- `replay` bir yakalamayı olduğu gibi yeniden gönderir veya eski kayıtların Stripe/Slack tarafından kabul edilmesi için **yeni bir zaman damgasıyla yeniden imzalar**
- Sırlar `--secret`, `--secret-env VAR` veya `HOOKPROBE_SECRET` ortam değişkeniyle verilebilir
- Betikler için `sign`, `verify` ve `replay` komutlarında `--json` çıktısı
- Üçüncü parti bağımlılık yok

## Gereksinimler

- Go 1.22 veya üzeri

## Kurulum

```bash
git clone https://github.com/yilmazmurad/hookprobe.git
cd hookprobe
go build -o hookprobe ./cmd/hookprobe
```

`GOPATH`/`GOBIN` altına kurmak için:

```bash
go install github.com/yilmazmurad/hookprobe/cmd/hookprobe@latest
```

## Kullanım

```text
hookprobe <komut> [bayraklar]

Komutlar:
  sign      Bir gövde için imza başlığı üretir
  verify    Bir imzayı veya istek başlığını gövdeye karşı doğrular
  listen    Gelen webhook'ları doğrulayan yerel bir yakalama sunucusu başlatır
  replay    Kaydedilmiş bir yakalamayı hedef bir URL'ye yeniden gönderir
  version   hookprobe sürümünü yazdırır
  help      Yardımı gösterir
```

### Bir gövdeyi imzalama

```bash
hookprobe sign --provider github --secret "$HOOK_SECRET" --payload body.json
# sha256=...

hookprobe sign --provider stripe --secret "$HOOK_SECRET" --payload body.json --timestamp 1700000000
# t=1700000000,v1=...

hookprobe sign --provider slack --secret "$HOOK_SECRET" --payload body.json --timestamp 1700000000
# v0=...   (stderr ayrıca X-Slack-Request-Timestamp basar)
```

`--payload -` (veya `--payload` vermemek) gövdeyi standart girdiden okur:

```bash
printf '{"ok":true}' | hookprobe sign --provider generic --secret "$HOOK_SECRET" --algo sha256 --encoding hex
```

### Bir imzayı doğrulama

```bash
hookprobe verify --provider github --secret "$HOOK_SECRET" --payload body.json --signature "sha256=..."
hookprobe verify --provider stripe --secret "$HOOK_SECRET" --payload body.json --header "t=1700000000,v1=..." --timestamp 1700000000
hookprobe verify --provider slack --secret "$HOOK_SECRET" --payload body.json \
  --signature "v0=..." --timestamp-header 1700000000
```

Makinece okunabilir sonuç için `--json` kullanın. Süreç imza geçerliyse `0`, değilse `1` ile çıkar.

Stripe ve Slack için varsayılan pencere `--tolerance 5m` değeridir. `--tolerance -1s` saat kontrolünü atlar; eski bir yakalamayı incelerken işe yarar.

### Yerel olarak dinleme

```bash
hookprobe listen --addr 127.0.0.1:8080 --provider auto --secret "$HOOK_SECRET" --save ./captures
```

Sağlayıcının "test webhook" aracını (veya `curl`) `http://127.0.0.1:8080/webhook` adresine yöneltin. Geçerli teslimatlar `200`, geçersizler `--accept-invalid` verilmedikçe `401` döner (`--accept-invalid` ile `202`). Kayıttan sonra isteği uygulamanıza iletmek için `--forward http://127.0.0.1:3000/hooks` ekleyin.

`auto` sağlayıcısı `Stripe-Signature`, `X-Slack-Signature` ve `X-Hub-Signature-256` / `X-Hub-Signature` başlıklarına bakar.

### Bir yakalamayı yeniden oynatma

```bash
hookprobe replay --file captures/20261113T200000.000000-abcd1234.json --target http://127.0.0.1:3000/webhook
```

Zaman damgalı sağlayıcılara taze bir imza vermek için:

```bash
hookprobe replay --file captures/....json --target http://127.0.0.1:3000/webhook --resign --secret "$HOOK_SECRET"
```

## Testler

```bash
gofmt -w .
go vet ./...
go test -v ./...
go build -o hookprobe ./cmd/hookprobe
```

## Proje düzeni

```text
cmd/hookprobe/          # ana giriş noktası
internal/signature/     # GitHub, Stripe, Slack ve genel HMAC
internal/capture/       # JSON yakalama biçimi, kaydetme/yükleme
internal/server/        # dinleme + iletme + yeniden oynatma
internal/cli/           # komut satırı arayüzü
```

## Lisans

[MIT](LICENSE) © 2026 Murat Yılmaz
