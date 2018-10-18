#ifndef _EFI_PCI_IO_H
#define _EFI_PCI_IO_H

#define EFI_PCI_IO_PROTOCOL \
    { 0x4cf5b200, 0x68b8, 0x4ca5, {0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a} }

INTERFACE_DECL(_EFI_PCI_IO);

typedef enum {
    EfiPciIoWidthUint8,
    EfiPciIoWidthUint16,
    EfiPciIoWidthUint32,
    EfiPciIoWidthUint64,
    EfiPciIoWidthFifoUint8,
    EfiPciIoWidthFifoUint16,
    EfiPciIoWidthFifoUint32,
    EfiPciIoWidthFifoUint64,
    EfiPciIoWidthFillUint8,
    EfiPciIoWidthFillUint16,
    EfiPciIoWidthFillUint32,
    EfiPciIoWidthFillUint64,
    EfiPciIoWidthMaximum
} EFI_PCI_IO_PROTOCOL_WIDTH;

#define EFI_PCI_IO_PASS_THROUGH_BAR 0xff

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_POLL_IO_MEM) (
  IN struct _EFI_PCI_IO *This,
  IN EFI_PCI_IO_PROTOCOL_WIDTH  Width,
  IN UINT8                      BarIndex,
  IN UINT64                     Offset,
  IN UINT64                     Mask,
  IN UINT64                     Value,
  IN UINT64                     Delay,
  OUT UINT64                    *Result
  );

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_IO_MEM) (
  IN struct _EFI_PCI_IO *This,
  IN EFI_PCI_IO_PROTOCOL_WIDTH  Width,
  IN UINT8                      BarIndex,
  IN UINT64                     Offset,
  IN UINTN                      Count,
  IN OUT VOID                   *Buffer
);

typedef struct {
  EFI_PCI_IO_PROTOCOL_IO_MEM    Read;
  EFI_PCI_IO_PROTOCOL_IO_MEM    Write;
} EFI_PCI_IO_PROTOCOL_ACCESS;

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_CONFIG) (
  IN struct _EFI_PCI_IO *This,
  IN EFI_PCI_IO_PROTOCOL_WIDTH  Width,
  IN UINT32                     Offset,
  IN UINTN                      Count,
  IN OUT VOID                   *Buffer
);

typedef struct {
  EFI_PCI_IO_PROTOCOL_CONFIG Read;
  EFI_PCI_IO_PROTOCOL_CONFIG Write;
} EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS;

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_COPY_MEM) (
  IN struct _EFI_PCI_IO *This,
  IN EFI_PCI_IO_PROTOCOL_WIDTH  Width,
  IN UINT8                      DestBarIndex,
  IN UINT64                     DestOffset,
  IN UINT8                      SrcBarIndex,
  IN UINT64                     SrcOffset,
  IN UINTN                      Count
  );

typedef enum {
    EfiPciIoOperationBusMasterRead,
    EfiPciIoOperationBusMasterWrite,
    EfiPciIoOperationBusMasterCommonBuffer,
    EfiPciIoOperationMaximum
} EFI_PCI_IO_PROTOCOL_OPERATION;

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_MAP) (
  IN struct _EFI_PCI_IO    *This,
  IN EFI_PCI_IO_PROTOCOL_OPERATION Operation,
  IN VOID                          *HostAddress,
  IN OUT UINTN                     *NumberOfBytes,
  OUT EFI_PHYSICAL_ADDRESS         *DeviceAddress,
  OUT VOID                         **Mapping
  );

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_UNMAP) (
  IN struct _EFI_PCI_IO *This,
  IN VOID                       *Mapping
);

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_ALLOCATE_BUFFER) (
  IN struct _EFI_PCI_IO *This,
  IN EFI_ALLOCATE_TYPE          Type,
  IN EFI_MEMORY_TYPE            MemoryType,
  IN UINTN                      Pages,
  OUT VOID                      **HostAddress,
  IN UINT64                     Attributes
  );

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_FREE_BUFFER) (
  IN struct _EFI_PCI_IO *This,
  IN UINTN                      Pages,
  IN VOID                       *HostAddress
  );

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_FLUSH) (
  IN struct _EFI_PCI_IO *This
  );

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_GET_LOCATION) (
  IN struct _EFI_PCI_IO *This,
  OUT UINTN                     *SegmentNumber,
  OUT UINTN                     *BusNumber,
  OUT UINTN                     *DeviceNumber,
  OUT UINTN                     *FunctionNumber
  );

#define EFI_PCI_IO_ATTRIBUTE_ISA_IO               0x0002
#define EFI_PCI_IO_ATTRIBUTE_VGA_PALETTE_IO       0x0004
#define EFI_PCI_IO_ATTRIBUTE_VGA_MEMORY           0x0008
#define EFI_PCI_IO_ATTRIBUTE_VGA_IO               0x0010
#define EFI_PCI_IO_ATTRIBUTE_IDE_PRIMARY_IO       0x0020
#define EFI_PCI_IO_ATTRIBUTE_IDE_SECONDARY_IO     0x0040
#define EFI_PCI_IO_ATTRIBUTE_MEMORY_WRITE_COMBINE 0x0080
#define EFI_PCI_IO_ATTRIBUTE_IO                   0x0100
#define EFI_PCI_IO_ATTRIBUTE_MEMORY               0x0200
#define EFI_PCI_IO_ATTRIBUTE_BUS_MASTER           0x0400
#define EFI_PCI_IO_ATTRIBUTE_MEMORY_CACHED        0x0800
#define EFI_PCI_IO_ATTRIBUTE_MEMORY_DISABLE       0x1000
#define EFI_PCI_IO_ATTRIBUTE_EMBEDDED_DEVICE      0x2000
#define EFI_PCI_IO_ATTRIBUTE_EMBEDDED_ROM         0x4000
#define EFI_PCI_IO_ATTRIBUTE_DUAL_ADDRESS_CYCLE   0x8000
#define EFI_PCI_IO_ATTRIBUTE_ISA_IO_16            0x10000
#define EFI_PCI_IO_ATTRIBUTE_VGA_PALETTE_IO_16    0x20000
#define EFI_PCI_IO_ATTRIBUTE_VGA_IO_16            0x40000

typedef enum {
    EfiPciIoAttributeOperationGet,
    EfiPciIoAttributeOperationSet,
    EfiPciIoAttributeOperationEnable,
    EfiPciIoAttributeOperationDisable,
    EfiPciIoAttributeOperationSupported,
    EfiPciIoAttributeOperationMaximum
} EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION;

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_ATTRIBUTES) (
  IN struct _EFI_PCI_IO             *This,
  IN EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION Operation,
  IN UINT64                                  Attributes,
  OUT UINT64                                 *Result OPTIONAL
  );

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_GET_BAR_ATTRIBUTES) (
  IN struct _EFI_PCI_IO *This,
  IN UINT8                      BarIndex,
  OUT UINT64                    *Supports OPTIONAL,
  OUT VOID                      **Resources OPTIONAL
  );

typedef
EFI_STATUS
(EFIAPI *EFI_PCI_IO_PROTOCOL_SET_BAR_ATTRIBUTES) (
  IN struct _EFI_PCI_IO *This,
  IN UINT64                     Attributes,
  IN UINT8                      BarIndex,
  IN OUT UINT64                 *Offset,
  IN OUT UINT64                 *Length
  );

typedef struct _EFI_PCI_IO {
  EFI_PCI_IO_PROTOCOL_POLL_IO_MEM        PollMem;
  EFI_PCI_IO_PROTOCOL_POLL_IO_MEM        PollIo;
  EFI_PCI_IO_PROTOCOL_ACCESS             Mem;
  EFI_PCI_IO_PROTOCOL_ACCESS             Io;
  EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS      Pci;
  EFI_PCI_IO_PROTOCOL_COPY_MEM           CopyMem;
  EFI_PCI_IO_PROTOCOL_MAP                Map;
  EFI_PCI_IO_PROTOCOL_UNMAP              Unmap;
  EFI_PCI_IO_PROTOCOL_ALLOCATE_BUFFER    AllocateBuffer;
  EFI_PCI_IO_PROTOCOL_FREE_BUFFER        FreeBuffer;
  EFI_PCI_IO_PROTOCOL_FLUSH              Flush;
  EFI_PCI_IO_PROTOCOL_GET_LOCATION       GetLocation;
  EFI_PCI_IO_PROTOCOL_ATTRIBUTES         Attributes;
  EFI_PCI_IO_PROTOCOL_GET_BAR_ATTRIBUTES GetBarAttributes;
  EFI_PCI_IO_PROTOCOL_SET_BAR_ATTRIBUTES SetBarAttributes;
  UINT64                                 RomSize;
  VOID                                   *RomImage;
} EFI_PCI_IO;

#endif /* _EFI_PCI_IO_H */
