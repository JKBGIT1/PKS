import struct
import array

'''
variable = input("Enter words: ")
print(variable)

for i in range(0, len(variable), 2):
    smallStr = variable[i:i+2]
    print(smallStr)
'''
# variable = struct.pack('ih', 0, 0)
# print(struct.calcsize('ih'))
# variable2 = {1: variable}
# variable3 = {1: variable, 2: ""}
# print(len(pickle.dumps(variable2)))
# print(len(pickle.dumps(variable3)))

hlavicka = struct.pack("cccHi", b'3', b'0', b'8', 0, 10)
print(struct.calcsize("cccHi"))
print(struct.calcsize("cH"))
print(struct.calcsize("cciH"))
# for i in struct.iter_unpack("c", hlavicka2):
#     bajtyHlavicka2 += b''.join(i)
# print(bajtyHlavicka2.decode("utf-8"))
# print(b'0123456789'.decode("utf-8"))
# bajty = b'0101100000'
# string = ""
# for i in :
#     string += i

# print(string)

# arr = [""] * 2
# arr[0] = (input("Zadaj prvy string"))
# arr[1] =(input("Zadaj druhy string"))
# for i in range(len(arr)):
#     print(arr[i])
#     i += 1

