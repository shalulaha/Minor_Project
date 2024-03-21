from tkinter import Tk, Canvas, Button, Text, Scrollbar, Label
from fetch_ip import fetch_ip_page
from port_scanner import port_scanner_page
from bandwidth_rate import bandwidth_rate_page

def main():
    window = Tk()
    window.geometry("602x590")
    window.configure(bg="#FFFFFF")
    window.title("Admin")

    canvas = Canvas(
        window,
        bg="#FFFFFF",
        height=590,
        width=602,
        bd=0,
        highlightthickness=0,
        relief="ridge"
    )
    canvas.place(x=0, y=0)
    canvas.create_rectangle(
        0.0,
        0.0,
        598.0,
        47.0,
        fill="#CAE8E5",
        outline=""
    )
    canvas.create_text(
        170.0,
        12.0,
        anchor="nw",
        text="NETWORK ADMINISTRATOR",
        fill="#000000",
        font=("IrishGrover Regular", 20 * -1)
    )

    fetch_ip_button = Button(
        window,
        text="FETCH IP",
        command=fetch_ip_page,
        font=("BalooBhai Regular", 14),
        bg="#53898D",
        fg="#FFFFFF",
    )
    fetch_ip_button.place(x=200, y=120, width=180, height=40)

    port_scanner_button = Button(
        window,
        text="PORT SCANNER",
        command=port_scanner_page,
        font=("BalooBhai Regular", 14),
        bg="#53898D",
        fg="#FFFFFF",
    )
    port_scanner_button.place(x=200, y=200, width=180, height=40)

    bandwidth_rate_button = Button(
        window,
        text="BANDWIDTH RATE",
        command=bandwidth_rate_page,
        font=("BalooBhai Regular", 14),
        bg="#53898D",
        fg="#FFFFFF",
    )
    bandwidth_rate_button.place(x=200, y=290, width=180, height=40)

    window.resizable(False, False)
    window.mainloop()

if __name__ == "__main__":
    main()
