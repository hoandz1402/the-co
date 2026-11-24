# Thế Cờ

Mở trực tiếp [index.html](index.html) để đấu với bot, chơi hai người cùng máy hoặc tạo phòng bạn bè qua PeerJS. Khi chạy qua máy chủ Node.js, mục **Chơi online** có thêm tài khoản, bảng Elo và phòng có AI hỗ trợ.

## Chơi tính Elo

- Đăng ký hoặc đăng nhập, chọn **Ván tính Elo**, tạo phòng và gửi mã hoặc link mời cho bạn bè. Người tham gia cũng cần đăng nhập.
- Tài khoản bắt đầu ở **1200 Elo**. Máy chủ kiểm tra nước đi, đồng hồ và kết quả, rồi cập nhật điểm của hai người theo công thức Elo với hệ số K = 32.
- Tài khoản admin có mục **Quản trị** để tìm, khóa và mở khóa tài khoản. Để sử dụng AI, admin chọn **Ván có AI hỗ trợ** khi tạo phòng. Người được mời phải đồng ý trước khi vào. Cả hai bên đều thấy nhãn AI hỗ trợ, còn nút **Gợi ý** dành cho admin khi đến lượt. Ván này không tính Elo.

## Chạy trên máy

Cần Node.js 22.13.1 trở lên trong dòng 22 hoặc Node.js 24.

Chạy `npm start` ở thư mục có `package.json` rồi mở `http://127.0.0.1:3000`. Dữ liệu mặc định nằm ở `data/the-co.sqlite`.

Để khởi tạo admin, đặt `ADMIN_USERNAME` và `ADMIN_PASSWORD` trong môi trường chạy trước lần khởi động đầu tiên. Chọn tên tài khoản mới và mật khẩu riêng từ 10–128 ký tự. Các lần khởi động sau giữ nguyên tài khoản trong cơ sở dữ liệu.

## Triển khai trên Render

1. Thêm `index.html`, `server.mjs`, `package.json`, `.gitignore` và `README.md` vào thư mục gốc của repo `hoandz1402/the-co`. Giữ thông tin đăng nhập và tệp cơ sở dữ liệu ở ngoài repo.
2. Trong Render, chọn **New → Web Service** và chọn repo trên nhánh `main`.
3. Chọn runtime **Node**, để trống **Root Directory**, đặt **Build Command** là `npm install`, **Start Command** là `npm start` và **Health Check Path** là `/healthz`.
4. Để giữ Elo qua các lần khởi động lại và triển khai, dùng gói Web Service có hỗ trợ **Persistent Disk**. Gắn ổ đĩa tại `/var/data` và đặt các biến môi trường sau.

   | Biến | Giá trị |
   |---|---|
   | `DB_PATH` | `/var/data/the-co.sqlite` |
   | `ADMIN_USERNAME` | Tên tài khoản admin bạn chọn |
   | `ADMIN_PASSWORD` | Mật khẩu riêng của admin |

5. Bấm **Deploy Web Service**. Mở URL của Web Service để đăng nhập và tạo phòng Elo. URL của Static Site cũ vẫn dùng được cho các chế độ chơi của bản HTML.

[Hướng dẫn Render Web Services](https://render.com/docs/web-services) · [Lưu dữ liệu bằng Persistent Disk](https://render.com/docs/disks)
