// Code generated by protoc-gen-go. DO NOT EDIT.
// source: executor.proto

package dkron

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type ExecuteRequest struct {
	JobName string            `protobuf:"bytes,1,opt,name=job_name,json=jobName,proto3" json:"job_name,omitempty"`
	Config  map[string]string `protobuf:"bytes,2,rep,name=config,proto3" json:"config,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (m *ExecuteRequest) Reset()         { *m = ExecuteRequest{} }
func (m *ExecuteRequest) String() string { return proto.CompactTextString(m) }
func (*ExecuteRequest) ProtoMessage()    {}
func (*ExecuteRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_12d1cdcda51e000f, []int{0}
}

func (m *ExecuteRequest) GetJobName() string {
	if m != nil {
		return m.JobName
	}
	return ""
}

func (m *ExecuteRequest) GetConfig() map[string]string {
	if m != nil {
		return m.Config
	}
	return nil
}

type ExecuteResponse struct {
	Output []byte `protobuf:"bytes,1,opt,name=output,proto3" json:"output,omitempty"`
	Error  string `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
}

func (m *ExecuteResponse) Reset()         { *m = ExecuteResponse{} }
func (m *ExecuteResponse) String() string { return proto.CompactTextString(m) }
func (*ExecuteResponse) ProtoMessage()    {}
func (*ExecuteResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_12d1cdcda51e000f, []int{1}
}

func (m *ExecuteResponse) GetOutput() []byte {
	if m != nil {
		return m.Output
	}
	return nil
}

func (m *ExecuteResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

func init() {
	proto.RegisterType((*ExecuteRequest)(nil), "dkron.ExecuteRequest")
	proto.RegisterMapType((map[string]string)(nil), "dkron.ExecuteRequest.ConfigEntry")
	proto.RegisterType((*ExecuteResponse)(nil), "dkron.ExecuteResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// ExecutorClient is the client API for Executor service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ExecutorClient interface {
	Execute(ctx context.Context, in *ExecuteRequest, opts ...grpc.CallOption) (*ExecuteResponse, error)
}

type executorClient struct {
	cc *grpc.ClientConn
}

func NewExecutorClient(cc *grpc.ClientConn) ExecutorClient {
	return &executorClient{cc}
}

func (c *executorClient) Execute(ctx context.Context, in *ExecuteRequest, opts ...grpc.CallOption) (*ExecuteResponse, error) {
	out := new(ExecuteResponse)
	err := c.cc.Invoke(ctx, "/dkron.Executor/Execute", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ExecutorServer is the server API for Executor service.
type ExecutorServer interface {
	Execute(context.Context, *ExecuteRequest) (*ExecuteResponse, error)
}

func RegisterExecutorServer(s *grpc.Server, srv ExecutorServer) {
	s.RegisterService(&_Executor_serviceDesc, srv)
}

func _Executor_Execute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExecuteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExecutorServer).Execute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dkron.Executor/Execute",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExecutorServer).Execute(ctx, req.(*ExecuteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Executor_serviceDesc = grpc.ServiceDesc{
	ServiceName: "dkron.Executor",
	HandlerType: (*ExecutorServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Execute",
			Handler:    _Executor_Execute_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "executor.proto",
}

func init() { proto.RegisterFile("executor.proto", fileDescriptor_12d1cdcda51e000f) }

var fileDescriptor_12d1cdcda51e000f = []byte{
	// 230 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4b, 0xad, 0x48, 0x4d,
	0x2e, 0x2d, 0xc9, 0x2f, 0xd2, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x4d, 0xc9, 0x2e, 0xca,
	0xcf, 0x53, 0x5a, 0xc8, 0xc8, 0xc5, 0xe7, 0x0a, 0x96, 0x49, 0x0d, 0x4a, 0x2d, 0x2c, 0x4d, 0x2d,
	0x2e, 0x11, 0x92, 0xe4, 0xe2, 0xc8, 0xca, 0x4f, 0x8a, 0xcf, 0x4b, 0xcc, 0x4d, 0x95, 0x60, 0x54,
	0x60, 0xd4, 0xe0, 0x0c, 0x62, 0xcf, 0xca, 0x4f, 0xf2, 0x4b, 0xcc, 0x4d, 0x15, 0xb2, 0xe4, 0x62,
	0x4b, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0x97, 0x60, 0x52, 0x60, 0xd6, 0xe0, 0x36, 0x52, 0xd4, 0x03,
	0x9b, 0xa2, 0x87, 0x6a, 0x82, 0x9e, 0x33, 0x58, 0x8d, 0x6b, 0x5e, 0x49, 0x51, 0x65, 0x10, 0x54,
	0x83, 0x94, 0x25, 0x17, 0x37, 0x92, 0xb0, 0x90, 0x00, 0x17, 0x73, 0x76, 0x6a, 0x25, 0xd4, 0x7c,
	0x10, 0x53, 0x48, 0x84, 0x8b, 0xb5, 0x2c, 0x31, 0xa7, 0x34, 0x55, 0x82, 0x09, 0x2c, 0x06, 0xe1,
	0x58, 0x31, 0x59, 0x30, 0x2a, 0xd9, 0x73, 0xf1, 0xc3, 0x2d, 0x28, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e,
	0x15, 0x12, 0xe3, 0x62, 0xcb, 0x2f, 0x2d, 0x29, 0x28, 0x2d, 0x01, 0x9b, 0xc0, 0x13, 0x04, 0xe5,
	0x81, 0x0c, 0x49, 0x2d, 0x2a, 0xca, 0x2f, 0x82, 0x19, 0x02, 0xe6, 0x18, 0xb9, 0x70, 0x71, 0xb8,
	0x42, 0x7d, 0x2f, 0x64, 0xc1, 0xc5, 0x0e, 0x35, 0x4c, 0x48, 0x14, 0xab, 0xeb, 0xa5, 0xc4, 0xd0,
	0x85, 0x21, 0x76, 0x26, 0xb1, 0x81, 0x03, 0xce, 0x18, 0x10, 0x00, 0x00, 0xff, 0xff, 0x67, 0xda,
	0xb8, 0x46, 0x4a, 0x01, 0x00, 0x00,
}
