#include <vector>
#include <string>
#include <iomanip>

class State {
public:
    State(const std::vector<uint8_t>& b){
        s.resize(16,0);
        if(b.size() > 16){
            throw std::invalid_argument("State constructor: input vector too large");
        }
        for(size_t i = 0; i < b.size(); ++i){
            s[i] = b[i];
        }
    }

    uint8_t get(int r, int c) const {
        return s[r + 4 * c];
    }

    std::vector<uint8_t> getBytes() const {
        return s;
    }

    void set(int r,int c,uint8_t value){
        s[r + 4 * c] = value;
    }

    std::string pprint() const {
        std::string str = "-------------\n";
        for(int i = 0; i < 4; ++i){
            for(int j = 0; j < 4; ++j){
                str += std::to_string(get(i,j)) + " ";
            }
            str += "\n-------------\n";
        }
        return str;
    }

private:
    std::vector<uint8_t> s;
};