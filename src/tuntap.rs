use std::{mem, os::raw::c_char};

use nix::{
    errno::Errno,
    fcntl::{open, OFlag},
    ioctl_write_int, ioctl_write_ptr_bad, libc,
    sys::{
        ioctl::ioctl_param_type,
        socket::{socket, AddressFamily, SockFlag, SockType, SockaddrIn},
        stat::Mode,
    },
    unistd::{read, write},
    Error,
};

ioctl_write_int!(tunsetiff, b'T', 202);
ioctl_write_ptr_bad!(siocsifaddr, libc::SIOCSIFADDR, libc::ifreq);
ioctl_write_ptr_bad!(siocsifnetmask, libc::SIOCSIFNETMASK, libc::ifreq);
ioctl_write_ptr_bad!(siocsifflags, libc::SIOCSIFFLAGS, libc::ifreq);

pub enum TunTapFlag {
    Tun,
    #[allow(dead_code)]
    Tap,
}

pub struct TunTap {
    fd: i32,
}

impl TunTap {
    pub fn new(flag: TunTapFlag) -> Result<TunTap, Error> {
        let fd = open("/dev/net/tun", OFlag::O_RDWR, Mode::empty())?;

        let mut ifr_name: [c_char; libc::IF_NAMESIZE] = [0; libc::IF_NAMESIZE];
        let name = match flag {
            TunTapFlag::Tun => b"tun0\0",
            TunTapFlag::Tap => b"tap0\0",
        };
        ifr_name[..name.len()].copy_from_slice(&name.map(|c| c as i8)[..]);

        // Create a interface
        let flag = match flag {
            TunTapFlag::Tun => libc::IFF_TUN,
            TunTapFlag::Tap => libc::IFF_TAP,
        };
        let ifru_flags = (flag | libc::IFF_NO_PI) as i16;
        let ifr_ifru = libc::__c_anonymous_ifr_ifru { ifru_flags };
        let ifreq = libc::ifreq { ifr_name, ifr_ifru };
        unsafe { tunsetiff(fd, &ifreq as *const libc::ifreq as ioctl_param_type) }?;

        let sock = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )?;

        // Assign 192.0.2.1 to the interface
        let ifru_addr = SockaddrIn::new(192, 0, 2, 1, 0);
        let ifru_addr = unsafe { mem::transmute(ifru_addr) };
        let ifr_ifru = libc::__c_anonymous_ifr_ifru { ifru_addr };
        let ifreq = libc::ifreq { ifr_name, ifr_ifru };
        unsafe { siocsifaddr(sock, &ifreq) }?;

        // Set the network mask for the interface to 255.255.255.0 (/24)
        let ifru_addr = SockaddrIn::new(255, 255, 255, 0, 0);
        let ifru_addr = unsafe { mem::transmute(ifru_addr) };
        let ifr_ifru = libc::__c_anonymous_ifr_ifru { ifru_addr };
        let ifreq = libc::ifreq { ifr_name, ifr_ifru };
        unsafe { siocsifnetmask(sock, &ifreq) }?;

        // Make the state of the interface up
        let ifru_flags = libc::IFF_UP as i16;
        let ifr_ifru = libc::__c_anonymous_ifr_ifru { ifru_flags };
        let ifreq = libc::ifreq { ifr_name, ifr_ifru };
        unsafe { siocsifflags(sock, &ifreq) }?;

        Ok(TunTap { fd })
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        read(self.fd, buf)
    }

    pub fn write(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        write(self.fd, buf)
    }
}
